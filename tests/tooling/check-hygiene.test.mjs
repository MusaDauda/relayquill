import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  checkCommitHistory,
  checkRepoHygiene,
  scanTextForHygiene
} from "../../tools/check-hygiene.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SPEC_DIR = ["Day", "05", "Relayquill"].join("-");

function git(cwd, args) {
  return execFileSync("git", ["-c", "user.name=Test Runner", "-c", "user.email=test@example.com", ...args], {
    cwd,
    encoding: "utf8"
  });
}

function createTempGitRepo(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rq-hygiene-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  git(dir, ["init", "-b", "main"]);
  return dir;
}

test("real repository passes hygiene check with zero self-false-positives", () => {
  const report = checkRepoHygiene(REPO_ROOT);
  assert.equal(report.ok, true, JSON.stringify(report.violations, null, 2));
  assert.equal(report.violations.length, 0);
});

test("clean temp git repo with ignore rules passes", (t) => {
  const dir = createTempGitRepo(t);
  fs.writeFileSync(path.join(dir, ".gitignore"), `/${SPEC_DIR}/\nnode_modules/\n`, "utf8");
  fs.writeFileSync(path.join(dir, ".dockerignore"), `/${SPEC_DIR}/\n.git/\n`, "utf8");
  fs.mkdirSync(path.join(dir, SPEC_DIR), { recursive: true });
  fs.writeFileSync(path.join(dir, SPEC_DIR, "notes.md"), "ignored external notes\n", "utf8");
  fs.writeFileSync(path.join(dir, "index.js"), "export const width = '40ch';\nexport const chName = 'channel';\n", "utf8");

  git(dir, ["add", ".gitignore", ".dockerignore", "index.js"]);
  git(dir, ["commit", "-m", "feat: initialize clean workspace"]);

  const report = checkRepoHygiene(dir);
  assert.equal(report.ok, true, JSON.stringify(report.violations, null, 2));
  assert.equal(report.commitsScanned, 1);
});

test("gitignore exempts only the exact exclusion line and flags forbidden comments", () => {
  const badWord = ["hand", "book"].join("");
  const text = `/${SPEC_DIR}/\n# ignore old ${badWord}\nnode_modules/\n`;
  const findings = scanTextForHygiene(text, { filePath: ".gitignore" });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
  assert.equal(findings[0].rule, "spec_doc_ref");
});

test("rejects forbidden terms, section citations, trailers, snake_case identifiers, and AI attribution", () => {
  const cases = [
    ["Day", " 05"].join(""),
    ["Day", "-05"].join(""),
    ["day", "05", "_ref"].join(""),
    ["hand", "book"].join(""),
    ["my_", "hand", "book_notes"].join(""),
    ["blue", "print"].join(""),
    ["blue", "print_v1"].join(""),
    ["chap", "ter 20"].join(""),
    ["ch", ".70"].join(""),
    ["ch", " 71"].join(""),
    ["Co", "Authored", "By: Bot"].join("-"),
    ["Cl", "aude"].join("")
  ];

  for (const sample of cases) {
    const findings = scanTextForHygiene(`// ${sample}\n`, { filePath: "src/app.ts" });
    assert.ok(findings.length >= 1, `Expected violation for sample: ${sample}`);
  }
});

test("does not false-positive on CSS 40ch, channel, or neutral rule identifiers", () => {
  const findings = scanTextForHygiene(
    "const style = { maxWidth: '40ch', width: '40ch;' }; const channel = 'provider'; const rules = ['spec_day_ref', 'spec_doc_ref', 'spec_plan_ref', 'section_num_ref'];\n",
    { filePath: "src/styles.ts" }
  );
  assert.equal(findings.length, 0);
});

test("rejects config files containing user paths (including lowercase Windows), .sock paths, or compound raw secret keys", () => {
  const homePath = `/${["ho", "me"].join("")}/dev/app.sock`;
  const findings1 = scanTextForHygiene(
    JSON.stringify({ ipc_path: homePath }),
    { filePath: "config/development.api.json" }
  );
  assert.ok(findings1.some((f) => f.rule === "config_hardcoded_user_path"));
  assert.ok(findings1.some((f) => f.rule === "config_hardcoded_sock_path"));

  const winLowerPath = `c:\\${["us", "ers"].join("")}\\alice\\app`;
  const findingsWinJson = scanTextForHygiene(
    JSON.stringify({ cache_dir: winLowerPath }),
    { filePath: "config/development.api.json" }
  );
  assert.ok(findingsWinJson.some((f) => f.rule === "config_hardcoded_user_path"));

  const findingsWinRaw = scanTextForHygiene(
    `cache_dir = "${winLowerPath}"\n`,
    { filePath: "config/release.backend.hcl" }
  );
  assert.ok(findingsWinRaw.some((f) => f.rule === "config_hardcoded_user_path"));

  const rawPassKey = ["pass", "word"].join("");
  const compoundDbPass = ["db_", "pass", "word"].join("");
  const compoundClientSec = ["client_", "sec", "ret"].join("");
  const compoundBearerTok = ["bearer_", "tok", "en"].join("");
  const findings2 = scanTextForHygiene(
    JSON.stringify({
      database: { [rawPassKey]: "not-allowed", [compoundDbPass]: "nope", password_secret_ref: "env:DB_PASS" },
      auth: { [compoundClientSec]: "nope", [compoundBearerTok]: "nope", secret_ref: "env:AUTH_SEC" }
    }),
    { filePath: "config/hosted.neon.api.json" }
  );
  const secretKeyFindings = findings2.filter((f) => f.rule === "config_raw_secret_key");
  assert.equal(secretKeyFindings.length, 4);

  const cleanConfigFindings = scanTextForHygiene(
    JSON.stringify({
      secret_provider: { mode: "aws_secrets_manager", secret_prefix: "/rq/prod" },
      database: { password_secret_ref: "env:DB_PASS" }
    }),
    { filePath: "config/release.api.json" }
  );
  assert.equal(cleanConfigFindings.length, 0);
});

test("detects forbidden terms in historical non-HEAD git commits", (t) => {
  const dir = createTempGitRepo(t);
  fs.writeFileSync(path.join(dir, ".gitignore"), `/${SPEC_DIR}/\n`, "utf8");
  fs.writeFileSync(path.join(dir, ".dockerignore"), `/${SPEC_DIR}/\n`, "utf8");
  git(dir, ["add", ".gitignore", ".dockerignore"]);
  const badTrailer = ["Co", "Authored", "By: Example <bot@example.com>"].join("-");
  git(dir, ["commit", "-m", `chore: initial\n\n${badTrailer}`]);

  fs.writeFileSync(path.join(dir, "README.md"), "Clean readme\n", "utf8");
  git(dir, ["add", "README.md"]);
  git(dir, ["commit", "-m", "docs: add clean readme"]);

  const history = checkCommitHistory(dir);
  assert.equal(history.commitsScanned, 2);
  assert.ok(history.violations.some((v) => v.rule === "attribution_trailer"));
});

test("rejects tracked file paths with forbidden terms even when file contents are clean", (t) => {
  const dir = createTempGitRepo(t);
  fs.writeFileSync(path.join(dir, ".gitignore"), `/${SPEC_DIR}/\n`, "utf8");
  fs.writeFileSync(path.join(dir, ".dockerignore"), `/${SPEC_DIR}/\n`, "utf8");
  const badDocPath = path.join(
    dir,
    "docs",
    `${["day", "05"].join("")}-${["hand", "book"].join("")}-${["chap", "ter70"].join("")}.md`
  );
  const badSrcPath = path.join(dir, "src", `${["cl", "aude"].join("")}-helper.ts`);
  fs.mkdirSync(path.dirname(badDocPath), { recursive: true });
  fs.mkdirSync(path.dirname(badSrcPath), { recursive: true });
  fs.writeFileSync(badDocPath, "# Clean Notes\nNothing forbidden in body.\n", "utf8");
  fs.writeFileSync(badSrcPath, "export const ok = true;\n", "utf8");

  git(dir, ["add", "."]);
  git(dir, ["commit", "-m", "chore: add files"]);

  const report = checkRepoHygiene(dir);
  assert.equal(report.ok, false);
  assert.ok(report.violations.some((v) => v.type === "path_hygiene" && v.rule === "spec_day_ref"));
  assert.ok(report.violations.some((v) => v.type === "path_hygiene" && v.rule === "spec_doc_ref"));
  assert.ok(report.violations.some((v) => v.type === "path_hygiene" && v.rule === "section_num_ref"));
  assert.ok(report.violations.some((v) => v.type === "path_hygiene" && v.rule === "ai_attribution"));
});

test("handles unborn repository with zero commits gracefully", (t) => {
  const dir = createTempGitRepo(t);
  const history = checkCommitHistory(dir);
  assert.equal(history.commitsScanned, 0);
  assert.deepEqual(history.violations, []);
});
