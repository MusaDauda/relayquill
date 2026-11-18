/* global document, window, getComputedStyle, EventSource */
import assert from 'node:assert/strict';

export function attachConsoleGuards(page, options = {}) {
  const errors = [];
  const pageErrors = [];
  const failedRequests = [];

  const onConsole = (msg) => {
    if (msg.type() === 'error') {
      errors.push(msg.text());
    }
  };
  const onPageError = (err) => {
    pageErrors.push(err instanceof Error ? err.message : String(err));
  };
  const onRequestFailed = (req) => {
    failedRequests.push(`${req.method()} ${req.url()}: ${req.failure()?.errorText ?? 'failed'}`);
  };

  page.on('console', onConsole);
  page.on('pageerror', onPageError);
  if (options.failOnRequestFailed) {
    page.on('requestfailed', onRequestFailed);
  }

  return {
    errors,
    pageErrors,
    failedRequests,
    assertClean() {
      assert.equal(errors.length, 0, `Unexpected console.error messages: ${errors.join(' | ')}`);
      assert.equal(pageErrors.length, 0, `Unexpected pageerror exceptions: ${pageErrors.join(' | ')}`);
      if (options.failOnRequestFailed) {
        assert.equal(
          failedRequests.length,
          0,
          `Unexpected failed requests: ${failedRequests.join(' | ')}`
        );
      }
    },
    detach() {
      page.off('console', onConsole);
      page.off('pageerror', onPageError);
      if (options.failOnRequestFailed) {
        page.off('requestfailed', onRequestFailed);
      }
    }
  };
}

export async function setupVirtualWebAuthn(page, options = {}) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', {
    enableUI: options.enableUI ?? false
  });

  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: options.isUserVerified ?? true,
      automaticPresenceSimulation: options.automaticPresenceSimulation ?? true,
      ...(options.authenticatorOptions ?? {})
    }
  });

  return {
    cdp,
    authenticatorId,
    async getCredentials() {
      const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
      return credentials;
    },
    async setUserVerified(isUserVerified) {
      await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified });
    },
    async setAutomaticPresenceSimulation(enabled) {
      await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled });
    },
    async remove() {
      await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
      await cdp.detach();
    }
  };
}

function linearizeChannel(channel255) {
  const srgb = channel255 / 255;
  return srgb <= 0.04045 ? srgb / 12.92 : ((srgb + 0.055) / 1.055) ** 2.4;
}

export function relativeLuminance(rgb) {
  const [r, g, b] = rgb;
  return 0.2126 * linearizeChannel(r) + 0.7152 * linearizeChannel(g) + 0.0722 * linearizeChannel(b);
}

export function contrastRatio(fgRgb, bgRgb) {
  const l1 = relativeLuminance(fgRgb);
  const l2 = relativeLuminance(bgRgb);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

export async function assertMinimumTargetSize(locator, minPx = 44) {
  const box = await locator.boundingBox();
  assert.ok(box, 'Target element has no bounding box (not visible)');
  assert.ok(
    box.width >= minPx && box.height >= minPx,
    `Interactive target too small: ${box.width}x${box.height}px (required >= ${minPx}x${minPx}px)`
  );
  return box;
}

export async function assertVisibleFocusIndicator(page, locator, options = {}) {
  const viaKeyboard = options.viaKeyboard ?? true;
  if (viaKeyboard) {
    await locator.evaluate((el) => {
      if (document.activeElement === el && typeof el.blur === 'function') {
        el.blur();
      }
    });
  }

  const before = await locator.evaluate((el) => {
    const cs = getComputedStyle(el);
    return {
      outlineStyle: cs.outlineStyle,
      outlineWidth: cs.outlineWidth,
      outlineColor: cs.outlineColor,
      boxShadow: cs.boxShadow
    };
  });

  if (viaKeyboard === 'tab' || viaKeyboard === 'shift-tab') {
    const key = viaKeyboard === 'shift-tab' ? 'Shift+Tab' : 'Tab';
    const maxTabs = options.maxTabs ?? 50;
    let reached = false;
    for (let i = 0; i < maxTabs; i += 1) {
      await page.keyboard.press(key);
      reached = await locator.evaluate((el) => document.activeElement === el);
      if (reached) {
        break;
      }
    }
    assert.equal(reached, true, `Element did not receive focus via ${key} within ${maxTabs} presses`);
  } else {
    if (viaKeyboard) {
      await page.keyboard.press('Shift');
    }
    await locator.focus();
  }
  const isFocused = await locator.evaluate((el) => document.activeElement === el);
  assert.equal(isFocused, true, 'Element did not receive keyboard focus');

  const after = await locator.evaluate((el) => {
    const cs = getComputedStyle(el);
    return {
      outlineStyle: cs.outlineStyle,
      outlineWidth: cs.outlineWidth,
      outlineColor: cs.outlineColor,
      boxShadow: cs.boxShadow
    };
  });

  const outlineWidthPx = Number.parseFloat(after.outlineWidth) || 0;
  const hasVisibleOutline = after.outlineStyle !== 'none' && outlineWidthPx > 0;
  const hasVisibleBoxShadow = after.boxShadow !== 'none' && after.boxShadow !== before.boxShadow;
  assert.ok(
    hasVisibleOutline || hasVisibleBoxShadow,
    `No visible focus indicator detected (before=${JSON.stringify(before)}, after=${JSON.stringify(after)})`
  );
  return after;
}

export async function assertContrastAA(page, selector, options = {}) {
  const measured = await page.locator(selector).first().evaluate((el) => {
    function parseRgba(str) {
      const trimmed = String(str).trim();
      const m = trimmed.match(/^rgba?\(([^)]+)\)$/i);
      if (!m) {
        throw new Error(`Unsupported CSS color format: "${str}"`);
      }
      const inner = m[1].trim();
      let r;
      let g;
      let b;
      let a = 1;
      if (inner.includes(',')) {
        const parts = inner.split(',').map((p) => Number.parseFloat(p.trim()));
        if (parts.length < 3 || parts.length > 4 || parts.some((n) => Number.isNaN(n))) {
          throw new Error(`Invalid CSS rgb/rgba color value: "${str}"`);
        }
        [r, g, b] = parts;
        if (parts.length === 4) {
          a = parts[3];
        }
      } else {
        const [rgbPart, alphaPart] = inner.split('/').map((s) => s.trim());
        const rgbTokens = rgbPart.split(/\s+/).map((p) => Number.parseFloat(p));
        if (rgbTokens.length !== 3 || rgbTokens.some((n) => Number.isNaN(n))) {
          throw new Error(`Invalid CSS rgb/rgba color value: "${str}"`);
        }
        [r, g, b] = rgbTokens;
        if (alphaPart !== undefined) {
          a = alphaPart.endsWith('%')
            ? Number.parseFloat(alphaPart) / 100
            : Number.parseFloat(alphaPart);
          if (Number.isNaN(a)) {
            throw new Error(`Invalid CSS alpha value in color: "${str}"`);
          }
        }
      }
      return [r, g, b, Math.min(1, Math.max(0, a))];
    }

    function compositeOver(fg, bg) {
      const a = fg[3];
      return [
        fg[0] * a + bg[0] * (1 - a),
        fg[1] * a + bg[1] * (1 - a),
        fg[2] * a + bg[2] * (1 - a),
        1
      ];
    }

    const cs = getComputedStyle(el);
    const fg = parseRgba(cs.color);

    const layers = [];
    let cur = el;
    while (cur) {
      layers.push(parseRgba(getComputedStyle(cur).backgroundColor));
      cur = cur.parentElement;
    }
    let bg = [255, 255, 255, 1];
    for (let i = layers.length - 1; i >= 0; i -= 1) {
      if (layers[i][3] > 0) {
        bg = compositeOver(layers[i], bg);
      }
    }

    const effectiveFg = fg[3] < 1 ? compositeOver(fg, bg) : fg;
    const fontSizePx = Number.parseFloat(cs.fontSize) || 16;
    const fontWeight = Number.parseInt(cs.fontWeight, 10) || 400;
    const isLarge = fontSizePx >= 24 || (fontSizePx >= 18.66 && fontWeight >= 700);

    return {
      fg: effectiveFg.slice(0, 3),
      bg: bg.slice(0, 3),
      fontSizePx,
      fontWeight,
      isLarge
    };
  });

  const ratio = contrastRatio(measured.fg, measured.bg);
  const largeText = options.largeText ?? measured.isLarge;
  const required = largeText ? 3.0 : 4.5;
  assert.ok(
    ratio >= required,
    `Contrast ratio ${ratio.toFixed(2)}:1 below WCAG AA ${required}:1 for ${selector} (fg=${measured.fg}, bg=${measured.bg})`
  );
  return { ratio, required, ...measured };
}

export async function assertAriaLiveStatus(page, selector) {
  const details = await page.locator(selector).first().evaluate((el) => {
    const ariaLive = el.getAttribute('aria-live');
    const role = el.getAttribute('role');
    const text = (el.textContent || '').trim();
    const hasIcon = Boolean(
      el.querySelector('svg, [data-status-icon], [aria-hidden="true"]')
    );
    return { ariaLive, role, text, hasIcon };
  });

  const isLive = details.ariaLive === 'polite' ||
    details.ariaLive === 'assertive' ||
    details.role === 'status' ||
    details.role === 'alert';

  assert.equal(isLive, true, `Element ${selector} is not a valid ARIA live/status region`);
  assert.ok(details.text.length > 0, `ARIA live region ${selector} has empty status text`);
  assert.equal(
    details.hasIcon,
    true,
    `Status region ${selector} must pair text with a non-color icon/badge indicator`
  );
  return details;
}

export async function assertModalFocusTrap(page, dialogSelector) {
  const dialog = page.locator(dialogSelector).first();
  await dialog.waitFor({ state: 'visible' });

  const semantics = await dialog.evaluate((el) => ({
    role: el.getAttribute('role'),
    ariaModal: el.getAttribute('aria-modal')
  }));
  assert.equal(semantics.role, 'dialog', 'Modal element must have role="dialog"');
  assert.equal(semantics.ariaModal, 'true', 'Modal element must have aria-modal="true"');

  const focusableCount = await dialog.evaluate((el) => {
    const items = el.querySelectorAll(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );
    return items.length;
  });
  assert.ok(focusableCount >= 2, 'Modal focus trap check requires at least 2 focusable controls');

  const selectorList =
    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  const forwardVisited = new Set();
  for (let i = 0; i < focusableCount + 2; i += 1) {
    await page.keyboard.press('Tab');
    const state = await dialog.evaluate((el, sel) => {
      const items = Array.from(el.querySelectorAll(sel));
      return {
        inside: el.contains(document.activeElement),
        index: items.indexOf(document.activeElement)
      };
    }, selectorList);
    assert.equal(state.inside, true, `Focus escaped modal dialog on Tab step ${i + 1}`);
    if (state.index >= 0) {
      forwardVisited.add(state.index);
    }
  }
  assert.ok(forwardVisited.size >= 2, 'Forward Tab did not cycle across modal controls');

  const backwardVisited = new Set();
  for (let i = 0; i < focusableCount + 2; i += 1) {
    await page.keyboard.press('Shift+Tab');
    const state = await dialog.evaluate((el, sel) => {
      const items = Array.from(el.querySelectorAll(sel));
      return {
        inside: el.contains(document.activeElement),
        index: items.indexOf(document.activeElement)
      };
    }, selectorList);
    assert.equal(state.inside, true, `Focus escaped modal dialog on Shift+Tab step ${i + 1}`);
    if (state.index >= 0) {
      backwardVisited.add(state.index);
    }
  }
  assert.ok(backwardVisited.size >= 2, 'Backward Shift+Tab did not wrap across modal controls');
}

export async function interceptSseStream(page, urlPattern, events = [], options = {}) {
  await page.route(urlPattern, async (route) => {
    const chunks = events.map((ev, index) => {
      const lines = [];
      lines.push(`id: ${ev.id ?? index + 1}`);
      if (ev.event) {
        lines.push(`event: ${ev.event}`);
      }
      const dataStr = typeof ev.data === 'string' ? ev.data : JSON.stringify(ev.data ?? {});
      lines.push(`data: ${dataStr}`);
      return `${lines.join('\n')}\n\n`;
    });

    await route.fulfill({
      status: options.status ?? 200,
      headers: {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache',
        ...(options.headers ?? {})
      },
      body: chunks.join('')
    });
  });
}

export async function collectBrowserSseEvents(page, sseUrl, options = {}) {
  const expectedCount = options.expectedCount ?? 1;
  const eventNames = options.eventNames ?? ['message'];
  const timeoutMs = options.timeoutMs ?? 5_000;

  return page.evaluate(
    ({ url, count, names, timeout }) => new Promise((resolve, reject) => {
      const collected = [];
      const es = new EventSource(url);
      const timer = window.setTimeout(() => {
        es.close();
        reject(new Error(`Timed out waiting for ${count} SSE events (got ${collected.length})`));
      }, timeout);

      const handleEvent = (ev) => {
        collected.push({
          type: ev.type,
          lastEventId: ev.lastEventId,
          data: ev.data
        });
        if (collected.length >= count) {
          window.clearTimeout(timer);
          es.close();
          resolve(collected);
        }
      };

      for (const name of names) {
        es.addEventListener(name, handleEvent);
      }
      es.onerror = () => {
        if (collected.length >= count) {
          window.clearTimeout(timer);
          es.close();
          resolve(collected);
        }
      };
    }),
    { url: sseUrl, count: expectedCount, names: eventNames, timeout: timeoutMs }
  );
}
