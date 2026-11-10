/* Only enqueued on the Reporter's settings screen. */
(() => {
  'use strict';
  const form = document.getElementById('mc-security-reporter-form');
  if (!form) return;
  const result = document.getElementById('mc-security-reporter-result');
  const token = document.getElementById('mc-security-reporter-token');
  const reload = document.getElementById('mc-security-reporter-reload');
  const status = document.getElementById('mc-security-reporter-status');
  let attempted = false;
  reload.addEventListener('click', () => { window.location.reload(); });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (attempted) return;
    const operation = event.submitter?.value;
    if (!operation) return;
    if (operation === 'reset_identity' && !window.confirm('Reset this cloned site identity and disable its API? Do not use this for an ordinary domain change.')) return;
    if (operation === 'rotate' && !window.confirm('Revoke the current token immediately and generate a replacement?')) return;
    let endpoint;
    try {
      // The hidden WordPress input named "action" shadows form.action in real browsers.
      const action = form.getAttribute('action');
      if (!action) throw new Error('Missing endpoint');
      endpoint = new URL(action, window.location.href);
      if (endpoint.origin !== window.location.origin) throw new Error('Cross-origin endpoint');
    } catch {
      result.textContent = 'The settings request URL is invalid. Reload settings before another action.';
      reload.hidden = false;
      return;
    }
    const body = new URLSearchParams(new FormData(form));
    body.set('operation', operation);
    attempted = true;
    form.querySelectorAll('button').forEach((button) => { button.disabled = true; });
    token.textContent = '';
    token.hidden = true;
    result.textContent = 'Working…';
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(endpoint.href, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { 'Accept': 'application/json' }, body, signal: controller.signal,
      });
      if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '')) {
        result.textContent = `Unexpected server response (HTTP ${response.status}). Reload settings and check the server logs. The request will not be retried automatically.`;
        return;
      }
      const payload = await response.json();
      if (!payload || typeof payload !== 'object' || typeof payload.success !== 'boolean') {
        result.textContent = 'The server returned an invalid response. Reload settings before another action.';
        return;
      }
      result.textContent = typeof payload.data?.message === 'string'
        ? payload.data.message.slice(0, 500) : `The action failed (HTTP ${response.status}). Reload settings before another action.`;
      const succeeds = response.ok && payload.success === true;
      if (succeeds && ['generate', 'rotate'].includes(operation) && !/^[a-f0-9]{64}$/.test(payload.data?.token ?? '')) {
        result.textContent = 'The server did not return a valid token. Reload settings and rotate if the API is enabled.';
        return;
      }
      if (succeeds && /^[a-f0-9]{64}$/.test(payload.data?.token ?? '')) {
        token.textContent = payload.data.token;
        token.hidden = false;
      }
      if (succeeds) status.textContent = ['generate', 'rotate'].includes(operation) ? 'Enabled' : 'Disabled';
    } catch {
      result.textContent = controller.signal.aborted
        ? 'The request timed out. Its result may be uncertain. Reload settings and rotate if needed. The request will not be retried automatically.'
        : 'The request failed (network, TLS, redirect or invalid JSON). Its result may be uncertain. Reload settings and rotate if needed. The request will not be retried automatically.';
    } finally {
      window.clearTimeout(timeout);
      reload.hidden = false;
    }
  });
  window.addEventListener('pagehide', () => { token.textContent = ''; token.hidden = true; });
  window.addEventListener('pageshow', (event) => { if (event.persisted) { token.textContent = ''; token.hidden = true; } });
  document.getElementById('mc-security-reporter-copy').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(document.getElementById('mc-security-reporter-config').value);
      result.textContent = 'Configuration example copied.';
    } catch {
      result.textContent = 'Select and copy the configuration example manually.';
    }
  });
})();
