/* global window */
import { expect, test } from '@playwright/test';
import {
  assertAriaLiveStatus,
  assertContrastAA,
  assertMinimumTargetSize,
  assertModalFocusTrap,
  assertVisibleFocusIndicator,
  attachConsoleGuards,
  collectBrowserSseEvents,
  interceptSseStream,
  setupVirtualWebAuthn
} from './console.mjs';
import { createE2EStack } from './stack.mjs';

const FIXTURE_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Relayquill Harness Smoke</title>
  <style>
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #ffffff;
      color: #0f172a;
      margin: 24px;
    }
    .btn {
      min-width: 140px;
      min-height: 48px;
      padding: 12px 20px;
      font-size: 16px;
      font-weight: 600;
      color: #ffffff;
      background: #1d4ed8;
      border: 2px solid #1e40af;
      border-radius: 6px;
      cursor: pointer;
    }
    .btn:focus-visible {
      outline: 3px solid #0f172a;
      outline-offset: 3px;
    }
    .status {
      margin-top: 16px;
      padding: 12px;
      color: #0f172a;
      background: #f1f5f9;
      border: 1px solid #94a3b8;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }
    .modal-backdrop[hidden] {
      display: none;
    }
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .modal {
      background: #ffffff;
      color: #0f172a;
      padding: 24px;
      border-radius: 8px;
    }
    .alpha-low-contrast {
      color: rgba(0, 0, 0, 0.2);
      background: #ffffff;
      font-size: 16px;
    }
  </style>
</head>
<body>
  <main>
    <h1 id="heading">Relayquill Console Smoke</h1>
    <button id="enroll-btn" class="btn" type="button">Enroll Passkey</button>
    <button id="open-modal-btn" class="btn" type="button">Open Confirm Modal</button>
    <p id="alpha-low-contrast" class="alpha-low-contrast">Low contrast translucent text</p>
    <div id="status-region" class="status" role="status" aria-live="polite">
      <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16">
        <circle cx="8" cy="8" r="6" fill="#15803d"></circle>
      </svg>
      <span id="status-text">Ready</span>
    </div>
  </main>

  <div id="modal-backdrop" class="modal-backdrop" hidden>
    <div id="confirm-modal" class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <h2 id="modal-title">Confirm Action</h2>
      <button id="modal-confirm" class="btn" type="button">Confirm</button>
      <button id="modal-close" class="btn" type="button">Close</button>
    </div>
  </div>

  <script>
    const statusText = document.getElementById('status-text');
    const modalBackdrop = document.getElementById('modal-backdrop');
    const modal = document.getElementById('confirm-modal');
    const modalConfirm = document.getElementById('modal-confirm');
    const modalClose = document.getElementById('modal-close');

    document.getElementById('open-modal-btn').addEventListener('click', () => {
      modalBackdrop.hidden = false;
      modalConfirm.focus();
    });

    modalClose.addEventListener('click', () => {
      modalBackdrop.hidden = true;
    });

    modal.addEventListener('keydown', (event) => {
      if (event.key !== 'Tab') return;
      const focusable = [modalConfirm, modalClose];
      const currentIdx = focusable.indexOf(document.activeElement);
      event.preventDefault();
      if (event.shiftKey) {
        const prev = currentIdx <= 0 ? focusable.length - 1 : currentIdx - 1;
        focusable[prev].focus();
      } else {
        const next = currentIdx === -1 || currentIdx >= focusable.length - 1 ? 0 : currentIdx + 1;
        focusable[next].focus();
      }
    });

    window.runPasskeyFlow = async () => {
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);
      const userId = new TextEncoder().encode('user-smoke-1');
      const created = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { id: window.location.hostname, name: 'Relayquill Smoke' },
          user: { id: userId, name: 'operator@relayquill.test', displayName: 'Operator Smoke' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
          timeout: 15000
        }
      });

      const assertionChallenge = new Uint8Array(32);
      crypto.getRandomValues(assertionChallenge);
      const asserted = await navigator.credentials.get({
        publicKey: {
          challenge: assertionChallenge,
          rpId: window.location.hostname,
          userVerification: 'required',
          timeout: 15000
        }
      });

      statusText.textContent = 'Passkey verified';
      return {
        createdId: created.id,
        assertedId: asserted.id,
        sameId: created.id === asserted.id
      };
    };
  </script>
</body>
</html>`;

test('console harness: CDP virtual WebAuthn, WCAG AA checks, console guards & SSE interception', async ({ page }) => {
  const stack = await createE2EStack({ pg: false, broker: false, receiver: false });
  const guards = attachConsoleGuards(page, { failOnRequestFailed: true });
  let webauthn = null;

  try {
    const server = await stack.startLocalHttpServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(FIXTURE_HTML);
        return;
      }
      res.writeHead(404);
      res.end('Not Found');
    });

    await interceptSseStream(page, '**/api/v1/events/watch*', [
      { id: '1', event: 'delivery.updated', data: { state: 'http_acknowledged', seq: 1 } },
      { id: '2', event: 'delivery.updated', data: { state: 'consumer_processed', seq: 2 } }
    ]);

    // WebAuthn requires localhost (not IP literal 127.0.0.1) for a valid RP ID.
    await page.goto(`${server.localhostOrigin}/`);
    await expect(page.locator('#heading')).toHaveText('Relayquill Console Smoke');

    webauthn = await setupVirtualWebAuthn(page);
    const passkeyRes = await page.evaluate(() => window.runPasskeyFlow());
    expect(passkeyRes.sameId).toBe(true);

    const creds = await webauthn.getCredentials();
    expect(creds.length).toBe(1);
    expect(creds[0].userName).toBe('operator@relayquill.test');

    // WCAG AA checks (including focus indicator after pointer interaction + translucent contrast rejection)
    await page.click('#enroll-btn');
    await assertMinimumTargetSize(page.locator('#enroll-btn'), 44);
    await assertVisibleFocusIndicator(page, page.locator('#enroll-btn'));
    await assertContrastAA(page, '#enroll-btn');
    await assertContrastAA(page, '#heading');
    await expect(assertContrastAA(page, '#alpha-low-contrast')).rejects.toThrow(/below WCAG AA 4\.5:1/);
    await assertAriaLiveStatus(page, '#status-region');

    // Modal focus trap check (verifies both Tab and Shift+Tab wrap)
    await page.click('#open-modal-btn');
    await assertModalFocusTrap(page, '#confirm-modal');
    await page.keyboard.press('Shift+Tab');
    const wrappedFocusId = await page.evaluate(() => document.activeElement?.id);
    expect(['modal-confirm', 'modal-close']).toContain(wrappedFocusId);

    // SSE interception + collection check
    const sseEvents = await collectBrowserSseEvents(
      page,
      `${server.localhostOrigin}/api/v1/events/watch?event_id=evt-1`,
      { expectedCount: 2, eventNames: ['delivery.updated'] }
    );
    expect(sseEvents.length).toBe(2);
    expect(JSON.parse(sseEvents[1].data).state).toBe('consumer_processed');

    guards.assertClean();
  } finally {
    if (webauthn) {
      await webauthn.remove();
    }
    guards.detach();
    await stack.cleanup();
  }
});
