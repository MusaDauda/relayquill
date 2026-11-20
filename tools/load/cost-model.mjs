import fs from "node:fs";
import path from "node:path";
import {
  CliError,
  findRawSecretsInObject,
  parseCliFlags,
  readStrictJsonFile,
  redactSensitiveData,
  runCliMain
} from "../release/lib/cli.mjs";

const DEFAULT_PRICE_DATE = "2026-01-15";

const HELP_TEXT = `Usage: node tools/load/cost-model.mjs [options]

Generate a dated infrastructure resource and cost worksheet covering separate
self-hosted (bare-metal / k3s / Kubernetes) and cloud (AWS EC2/systemd and EKS)
deployment profiles, keeping steady monthly cost, temporary recovery burn, and
post-teardown retained artifact costs distinct.

Options:
  --profile <name>      Profile filter: all | self_hosted | cloud | cloud_ec2 | cloud_eks (default: all)
  --region <name>       Target cloud or facility region label (default: us-east-1)
  --price-date <date>   ISO YYYY-MM-DD pricing snapshot date (default: ${DEFAULT_PRICE_DATE})
  --currency <code>     Currency code (default: USD)
  --input <path>        Optional strict JSON array of custom dated resource line items
  --format <fmt>        Output format: json | csv (default: json)
  --out <path>          Write cost worksheet JSON or CSV to path
  --json                Force structured JSON output on stdout
  -h, --help            Show help without reading secrets or mutating state
`;

const BASELINE_LINE_ITEMS = [
  // Self-hosted steady monthly profile
  {
    scenario_name: "self_hosted",
    profile_kind: "self_hosted",
    resource: "Application & Console Hosts (2x 4 vCPU / 8 GiB nodes)",
    unit: "node-month",
    quantity: 2,
    unit_price: 48.0,
    source_url: "https://www.hetzner.com/cloud/",
    assumption_reference: "selfhosted-app-compute-v1",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "self_hosted",
    profile_kind: "self_hosted",
    resource: "Dedicated PostgreSQL 18 Primary Node (4 vCPU / 16 GiB + NVMe)",
    unit: "node-month",
    quantity: 1,
    unit_price: 84.0,
    source_url: "https://www.hetzner.com/cloud/",
    assumption_reference: "selfhosted-postgres-primary-v1",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "self_hosted",
    profile_kind: "self_hosted",
    resource: "3-Node NATS JetStream Quorum Cluster (3x 2 vCPU / 4 GiB)",
    unit: "node-month",
    quantity: 3,
    unit_price: 18.0,
    source_url: "https://www.hetzner.com/cloud/",
    assumption_reference: "selfhosted-jetstream-quorum-v1",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "self_hosted",
    profile_kind: "self_hosted",
    resource: "Encrypted PostgreSQL WAL & Snapshot Object Backup Storage",
    unit: "GiB-month",
    quantity: 250,
    unit_price: 0.02,
    source_url: "https://www.hetzner.com/storage/object-storage/",
    assumption_reference: "selfhosted-pg-backup-14d-v1",
    measured_or_assumed: "assumed",
    retained_after_teardown: true,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "self_hosted",
    profile_kind: "self_hosted",
    resource: "Isolated Restore Drill Temporary PostgreSQL Node (1-day drill)",
    unit: "node-day",
    quantity: 1,
    unit_price: 3.0,
    source_url: "https://www.hetzner.com/cloud/",
    assumption_reference: "selfhosted-isolated-restore-drill-v1",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "one_off_experiment"
  },

  // Cloud AWS EC2/systemd steady monthly profile
  {
    scenario_name: "cloud_ec2",
    profile_kind: "cloud",
    resource: "EC2 Role Hosts (api, sender, relay, fanout, coordinator, console)",
    unit: "instance-hour",
    quantity: 4380,
    unit_price: 0.0416,
    source_url: "https://aws.amazon.com/ec2/pricing/on-demand/",
    assumption_reference: "aws-ec2-t3-medium-6hosts-730h",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "cloud_ec2",
    profile_kind: "cloud",
    resource: "3-Node NATS JetStream EC2 Hosts + Encrypted GP3 Volumes",
    unit: "node-month",
    quantity: 3,
    unit_price: 38.37,
    source_url: "https://aws.amazon.com/ebs/pricing/",
    assumption_reference: "aws-ec2-nats-3node-100gb-gp3",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "cloud_ec2",
    profile_kind: "cloud",
    resource: "RDS PostgreSQL 18 Single/Multi-AZ Compute + GP3 Storage + Backups",
    unit: "cluster-month",
    quantity: 1,
    unit_price: 168.5,
    source_url: "https://aws.amazon.com/rds/postgresql/pricing/",
    assumption_reference: "aws-rds-pg18-db-m6g-large-100gb",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "cloud_ec2",
    profile_kind: "cloud",
    resource: "Application Load Balancer + NAT Gateway + KMS + Secrets Manager",
    unit: "stack-month",
    quantity: 1,
    unit_price: 68.4,
    source_url: "https://aws.amazon.com/elasticloadbalancing/pricing/",
    assumption_reference: "aws-alb-nat-kms-secrets-v1",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "cloud_ec2",
    profile_kind: "cloud",
    resource: "Retained EBS/RDS Snapshots, ECR Images & CloudWatch Logs",
    unit: "archive-month",
    quantity: 1,
    unit_price: 14.5,
    source_url: "https://aws.amazon.com/cloudwatch/pricing/",
    assumption_reference: "aws-retained-snapshots-ecr-logs-v1",
    measured_or_assumed: "assumed",
    retained_after_teardown: true,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "cloud_ec2",
    profile_kind: "cloud",
    resource: "Temporary RDS Isolated PITR Restore Target (24h verification)",
    unit: "instance-day",
    quantity: 1,
    unit_price: 5.62,
    source_url: "https://aws.amazon.com/rds/postgresql/pricing/",
    assumption_reference: "aws-rds-isolated-restore-24h-v1",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "one_off_experiment"
  },

  // Cloud AWS EKS steady monthly profile
  {
    scenario_name: "cloud_eks",
    profile_kind: "cloud",
    resource: "Amazon EKS Cluster Control Plane",
    unit: "cluster-hour",
    quantity: 730,
    unit_price: 0.1,
    source_url: "https://aws.amazon.com/eks/pricing/",
    assumption_reference: "aws-eks-control-plane-730h",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "cloud_eks",
    profile_kind: "cloud",
    resource: "EKS Managed Worker Nodes (3 AZ spread, 3x m6i.large)",
    unit: "node-hour",
    quantity: 2190,
    unit_price: 0.096,
    source_url: "https://aws.amazon.com/ec2/pricing/on-demand/",
    assumption_reference: "aws-eks-3-nodes-3az-730h",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "cloud_eks",
    profile_kind: "cloud",
    resource: "RDS PostgreSQL 18 + External 3-Node NATS Broker Cluster",
    unit: "backing-month",
    quantity: 1,
    unit_price: 283.61,
    source_url: "https://aws.amazon.com/rds/postgresql/pricing/",
    assumption_reference: "aws-eks-backing-pg-nats-v1",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "cloud_eks",
    profile_kind: "cloud",
    resource: "AWS Load Balancer Controller + NAT + Pod Identity + Secrets + KMS",
    unit: "stack-month",
    quantity: 1,
    unit_price: 72.0,
    source_url: "https://aws.amazon.com/vpc/pricing/",
    assumption_reference: "aws-eks-ingress-nat-secrets-v1",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "cloud_eks",
    profile_kind: "cloud",
    resource: "Retained ECR Digests, RDS Snapshots & Audit Log Archives",
    unit: "archive-month",
    quantity: 1,
    unit_price: 16.0,
    source_url: "https://aws.amazon.com/ecr/pricing/",
    assumption_reference: "aws-eks-retained-artifacts-v1",
    measured_or_assumed: "assumed",
    retained_after_teardown: true,
    billing_cadence: "monthly_steady"
  },
  {
    scenario_name: "cloud_eks",
    profile_kind: "cloud",
    resource: "Temporary EKS Failure Drill + RDS PITR Isolated Restore (24h)",
    unit: "drill-day",
    quantity: 1,
    unit_price: 8.5,
    source_url: "https://aws.amazon.com/rds/postgresql/pricing/",
    assumption_reference: "aws-eks-isolated-restore-24h-v1",
    measured_or_assumed: "assumed",
    retained_after_teardown: false,
    billing_cadence: "one_off_experiment"
  }
];

function roundCurrency(amount) {
  return Math.round(amount * 100) / 100;
}

function validateLineItem(raw, index, defaults) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new CliError(`Line item[${index}] must be a JSON object`, 1);
  }
  const quantity = Number(raw.quantity);
  const unitPrice = Number(raw.unit_price);
  if (!Number.isFinite(quantity) || quantity < 0) {
    throw new CliError(`Line item[${index}] quantity must be a non-negative finite number`, 1);
  }
  if (!Number.isFinite(unitPrice) || unitPrice < 0) {
    throw new CliError(`Line item[${index}] unit_price must be a non-negative finite number`, 1);
  }
  const priceDate = String(raw.price_date ?? defaults.priceDate);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(priceDate)) {
    throw new CliError(`Line item[${index}] price_date must be YYYY-MM-DD, got "${priceDate}"`, 1);
  }
  const sourceUrl = String(raw.source_url ?? "");
  if (!/^https:\/\//i.test(sourceUrl)) {
    throw new CliError(`Line item[${index}] source_url must be an https:// pricing reference`, 1);
  }
  const scenarioName = String(raw.scenario_name ?? "").trim();
  const profileKind = String(raw.profile_kind ?? (scenarioName === "self_hosted" ? "self_hosted" : "cloud"));
  if (profileKind !== "self_hosted" && profileKind !== "cloud") {
    throw new CliError(`Line item[${index}] profile_kind must be self_hosted or cloud`, 1);
  }
  const subtotal = roundCurrency(quantity * unitPrice);
  return {
    scenario_name: scenarioName,
    profile_kind: profileKind,
    resource: String(raw.resource ?? ""),
    region: String(raw.region ?? defaults.region),
    unit: String(raw.unit ?? "unit"),
    quantity,
    unit_price: unitPrice,
    currency: String(raw.currency ?? defaults.currency),
    price_date: priceDate,
    source_url: sourceUrl,
    subtotal,
    assumption_reference: String(raw.assumption_reference ?? "custom"),
    measured_or_assumed: raw.measured_or_assumed === "measured" ? "measured" : "assumed",
    retained_after_teardown: Boolean(raw.retained_after_teardown),
    billing_cadence: raw.billing_cadence === "one_off_experiment" ? "one_off_experiment" : "monthly_steady"
  };
}

function escapeCsvField(val) {
  const str = String(val ?? "");
  if (str.includes(",") || str.includes("\"") || str.includes("\n")) {
    return `"${str.replace(/"/g, "\"\"")}"`;
  }
  return str;
}

export function renderWorksheetCsv(items) {
  const headers = [
    "scenario_name",
    "profile_kind",
    "resource",
    "region",
    "unit",
    "quantity",
    "unit_price",
    "currency",
    "price_date",
    "source_url",
    "subtotal",
    "assumption_reference",
    "measured_or_assumed",
    "retained_after_teardown",
    "billing_cadence"
  ];
  const lines = [headers.join(",")];
  for (const item of items) {
    lines.push(headers.map((h) => escapeCsvField(item[h])).join(","));
  }
  return `${lines.join("\n")}\n`;
}

export function buildCostModelWorksheet(options = {}) {
  const region = options.region ?? "us-east-1";
  const priceDate = options.priceDate ?? DEFAULT_PRICE_DATE;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(priceDate)) {
    throw new CliError(`Invalid --price-date "${priceDate}"; expected YYYY-MM-DD`, 1);
  }
  const currency = options.currency ?? "USD";
  const profileFilter = options.profile ?? "all";

  let rawItems = BASELINE_LINE_ITEMS;
  if (options.inputPath) {
    const custom = readStrictJsonFile(options.inputPath);
    const secretFindings = findRawSecretsInObject(custom, "$");
    if (secretFindings.length > 0) {
      throw new CliError(`Refusing cost input with raw secrets:\n- ${secretFindings.join("\n- ")}`, 1);
    }
    rawItems = Array.isArray(custom) ? custom : Array.isArray(custom.items) ? custom.items : [];
    if (rawItems.length === 0) {
      throw new CliError("Custom cost input contains zero line items", 1);
    }
  }

  const normalized = rawItems.map((item, idx) =>
    validateLineItem(item, idx, { region, priceDate, currency })
  );

  const filtered = normalized.filter((item) => {
    if (profileFilter === "all") {
      return true;
    }
    if (profileFilter === "self_hosted") {
      return item.profile_kind === "self_hosted";
    }
    if (profileFilter === "cloud") {
      return item.profile_kind === "cloud";
    }
    return item.scenario_name === profileFilter;
  });

  const scenarioMap = new Map();
  for (const item of filtered) {
    let summary = scenarioMap.get(item.scenario_name);
    if (!summary) {
      summary = {
        scenario_name: item.scenario_name,
        profile_kind: item.profile_kind,
        region,
        currency,
        price_date: priceDate,
        monthly_steady_total: 0,
        one_off_experiment_total: 0,
        retained_after_teardown_monthly_total: 0,
        teardown_deadline_note: "Temporary restore/load targets carry a 24h teardown review deadline.",
        item_count: 0
      };
      scenarioMap.set(item.scenario_name, summary);
    }
    summary.item_count += 1;
    if (item.billing_cadence === "one_off_experiment") {
      summary.one_off_experiment_total = roundCurrency(summary.one_off_experiment_total + item.subtotal);
    } else {
      summary.monthly_steady_total = roundCurrency(summary.monthly_steady_total + item.subtotal);
    }
    if (item.retained_after_teardown) {
      summary.retained_after_teardown_monthly_total = roundCurrency(
        summary.retained_after_teardown_monthly_total + item.subtotal
      );
    }
  }

  const worksheet = redactSensitiveData({
    ok: true,
    worksheet_version: 1,
    price_date: priceDate,
    currency,
    region,
    profile_filter: profileFilter,
    scenarios_kept_independent: true,
    disclaimer:
      "Dated reference pricing inputs only; scenarios are never summed as one active topology, and actual billing requires account-specific verification.",
    scenarios: Array.from(scenarioMap.values()),
    line_items: filtered
  });

  if (options.outPath) {
    const resolvedOut = path.resolve(options.outPath);
    fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
    if (options.format === "csv" || resolvedOut.toLowerCase().endsWith(".csv")) {
      fs.writeFileSync(resolvedOut, renderWorksheetCsv(filtered), "utf8");
    } else {
      fs.writeFileSync(resolvedOut, `${JSON.stringify(worksheet, null, 2)}\n`, "utf8");
    }
  }

  return worksheet;
}

runCliMain(import.meta.url, HELP_TEXT, (argv) => {
  const parsed = parseCliFlags(argv, {
    options: {
      "--profile": {
        type: "string",
        enum: ["all", "self_hosted", "cloud", "cloud_ec2", "cloud_eks"],
        default: "all"
      },
      "--region": { type: "string", default: "us-east-1" },
      "--price-date": { type: "string", default: DEFAULT_PRICE_DATE },
      "--currency": { type: "string", default: "USD" },
      "--input": { type: "string" },
      "--format": { type: "string", enum: ["json", "csv"], default: "json" },
      "--out": { type: "string" },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }
  const worksheet = buildCostModelWorksheet({
    profile: parsed.options["--profile"],
    region: parsed.options["--region"],
    priceDate: parsed.options["--price-date"],
    currency: parsed.options["--currency"],
    inputPath: parsed.options["--input"],
    format: parsed.options["--format"],
    outPath: parsed.options["--out"]
  });

  if (parsed.options["--json"]) {
    return { exitCode: 0, output: worksheet };
  }
  if (parsed.options["--format"] === "csv") {
    return { exitCode: 0, output: renderWorksheetCsv(worksheet.line_items).trimEnd() };
  }
  const parts = worksheet.scenarios.map(
    (s) => `${s.scenario_name}=$${s.monthly_steady_total}/mo(one_off=$${s.one_off_experiment_total})`
  );
  return {
    exitCode: 0,
    output: `[cost-model] price_date=${worksheet.price_date} ${parts.join(" ")}`
  };
});
