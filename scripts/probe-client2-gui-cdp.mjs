// Connectivity evidence only. This never evaluates full GUI acceptance or G1.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const [portText, output, phase] = process.argv.slice(2);
assert.equal(process.platform, 'win32');
assert.equal(Number(process.versions.node.split('.')[0]), 24);
assert.match(portText ?? '', /^\d+$/);
const port = Number(portText);
assert(port > 0 && port < 65536 && output);
assert(['discover', 'input'].includes(phase));
const report = { phase, cdp_connected: false, workspace_loaded: false,
  gui_input_observed: false, screenshot_saved: false,
  input_scope: 'trusted mousemove in original WebView only; no feature acceptance',
  full_gui_acceptance: 'not-evaluated', g1_passed: false };
let socket;
try {
  const origin = `http://127.0.0.1:${port}`;
  let version;
  const deadline = Date.now() + 25000;
  while (!version && Date.now() < deadline) {
    try {
      const response = await fetch(`${origin}/json/version`, { signal: AbortSignal.timeout(1000) });
      assert(response.ok);
      version = await response.json();
    } catch { await new Promise(resolve => setTimeout(resolve, 250)); }
  }
  assert(version, 'Original WebView CDP endpoint did not become ready');
  const endpoint = new URL(version.webSocketDebuggerUrl);
  assert.equal(endpoint.protocol, 'ws:');
  assert(['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname));
  assert.equal(endpoint.port, portText);
  socket = new WebSocket(endpoint);
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(Error('CDP connection timeout')), 5000);
    socket.addEventListener('open', () => { clearTimeout(timeout); resolve(); }, { once: true });
    socket.addEventListener('error', () => { clearTimeout(timeout); reject(Error('CDP socket failed')); }, { once: true });
  });
  let nextId = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const reply = JSON.parse(event.data);
    const entry = pending.get(reply.id);
    if (!entry) return;
    pending.delete(reply.id); clearTimeout(entry.timeout);
    if (reply.error) entry.reject(Error(`CDP ${entry.method}: ${reply.error.message}`));
    else entry.resolve(reply.result);
  });
  function call(method, params = {}, sessionId) {
    return new Promise((resolve, reject) => {
      const id = ++nextId;
      const timeout = setTimeout(() => { pending.delete(id); reject(Error(`CDP timeout: ${method}`)); }, 5000);
      pending.set(id, { method, resolve, reject, timeout });
      socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  report.browser = await call('Browser.getVersion');
  const processes = await call('SystemInfo.getProcessInfo');
  const browser = processes.processInfo.filter(p => p.type === 'browser');
  assert.equal(browser.length, 1, 'Require one CDP browser process for native ownership binding');
  report.browser_pid = browser[0].id;
  let target;
  while (!target && Date.now() < deadline) {
    const targets = await call('Target.getTargets');
    const pages = targets.targetInfos.filter(t => {
      try { return t.type === 'page' && new URL(t.url).pathname === '/workspace.html'; }
      catch { return false; }
    });
    assert(pages.length <= 1, 'Ambiguous original workspace target');
    target = pages[0];
    if (!target) await new Promise(resolve => setTimeout(resolve, 250));
  }
  assert(target, 'Original /workspace.html page not found');
  report.target = { id: target.targetId, url: target.url, title: target.title };
  if (phase === 'input') {
    const bound = JSON.parse(await readFile(join(output, 'native-bound.json'), 'utf8'));
    assert.equal(bound.browser_pid, report.browser_pid);
    assert.equal(bound.port, port);
    assert.equal(bound.target_id, target.targetId);
  }
  const { sessionId } = await call('Target.attachToTarget', { targetId: target.targetId, flatten: true });
  async function evaluate(expression) {
    const response = await call('Runtime.evaluate', { expression, returnByValue: true }, sessionId);
    assert(!response.exceptionDetails, 'JavaScript evaluation raised an exception');
    return response.result.value;
  }
  do {
    report.page = await evaluate(`({ready:document.readyState,title:document.title,
      version:document.querySelector('#client-version')?.textContent,
      width:innerWidth,height:innerHeight,workspace:!!document.querySelector('#view')})`);
    if (['interactive', 'complete'].includes(report.page.ready) && report.page.workspace) break;
    await new Promise(resolve => setTimeout(resolve, 250));
  } while (Date.now() < deadline);
  assert(['interactive', 'complete'].includes(report.page.ready));
  assert(report.page.workspace && report.page.width > 0 && report.page.height > 0);
  report.cdp_connected = true;
  report.workspace_loaded = true;
  if (phase === 'input') {
    // Observe a trusted renderer input without changing product preferences or invoking RPC.
    await evaluate(`(() => { window.__respireGuiProbeMove = null;
      document.addEventListener('mousemove', e => { window.__respireGuiProbeMove =
        {trusted:e.isTrusted,x:e.clientX,y:e.clientY}; }, {once:true,capture:true}); return true; })()`);
    await call('Input.dispatchMouseEvent', { type: 'mouseMoved', x: 17, y: 19 }, sessionId);
    report.input = await evaluate('window.__respireGuiProbeMove');
    assert(report.input?.trusted === true && report.input.x === 17 && report.input.y === 19,
      'CDP mouse input was not observed by the original document');
    report.gui_input_observed = true;
    const shot = await call('Page.captureScreenshot', { format: 'png' }, sessionId);
    await writeFile(join(output, 'workspace.png'), Buffer.from(shot.data, 'base64'));
    report.screenshot_saved = true;
  }
} catch (error) {
  report.error = error.message;
  process.exitCode = 1;
} finally {
  socket?.close();
  await writeFile(join(output, phase === 'discover' ? 'cdp-discovery.json' : 'cdp.json'), JSON.stringify(report, null, 2) + '\n');
}
