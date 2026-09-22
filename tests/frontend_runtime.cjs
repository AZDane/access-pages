const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");

class Clock {
  now = 100000;
  nextId = 1;
  tasks = new Map();

  setTimeout = (callback, delay) => {
    const id = this.nextId++;
    this.tasks.set(id, {callback, due: this.now + delay});
    return id;
  };

  clearTimeout = (id) => this.tasks.delete(id);

  delays() {
    return [...this.tasks.values()].map((task) => task.due - this.now).sort((a, b) => a - b);
  }

  async advance(milliseconds) {
    const until = this.now + milliseconds;
    while (true) {
      const next = [...this.tasks.entries()].sort((a, b) => a[1].due - b[1].due)[0];
      if (!next || next[1].due > until) break;
      this.now = next[1].due;
      this.tasks.delete(next[0]);
      next[1].callback();
      await settle();
    }
    this.now = until;
    await settle();
  }
}

async function settle() {
  for (let i = 0; i < 20; i++) await Promise.resolve();
}

class Element {
  constructor() {
    this.children = [];
    this.dataset = {};
    this.style = {};
    this.listeners = new Map();
    this.attributes = new Map();
    this.classList = {
      add() {}, remove() {}, toggle() {}, contains() { return false; },
    };
    this.value = "";
    this.open = false;
  }
  addEventListener(name, callback) { this.listeners.set(name, callback); }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes.set(name, value); }
  getAttribute(name) { return name === "src" ? this.src || null : this.attributes.get(name) || null; }
  removeAttribute(name) { this.attributes.delete(name); if (name === "src") this.src = ""; }
  close() { this.open = false; }
  showModal() { this.open = true; }
  focus() {}
}

function harness(name, api) {
  const clock = new Clock();
  const elements = new Map();
  const documentEvents = new Map();
  const windowEvents = new Map();
  const navigations = [];
  const document = {
    hidden: false,
    baseURI: "https://ha.example/api/hassio_ingress/session/",
    documentElement: {dataset: {pageId: "fixture"}},
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, new Element());
      return elements.get(id);
    },
    createElement() { return new Element(); },
    querySelectorAll() { return []; },
    addEventListener(event, callback) { documentEvents.set(event, callback); },
  };
  const location = {
    origin: "https://ha.example",
    pathname: "/api/hassio_ingress/session/admin",
    search: "",
    replace(url) { navigations.push(url); },
    reload() { throw new Error("Unexpected reload"); },
  };
  const window = {
    location,
    setTimeout: clock.setTimeout,
    addEventListener(event, callback) { windowEvents.set(event, callback); },
  };
  class FakeDate extends Date { static now() { return clock.now; } }
  const context = vm.createContext({
    document, window, navigator: {onLine: true}, URL, URLSearchParams,
    Date: FakeDate, setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout,
    sessionStorage: {getItem() { return null; }, setItem() {}},
    history: {replaceState() {}},
    createAdminApi: () => api,
    createAccessApi: () => api,
    AccessConnectionError: class AccessConnectionError extends Error {},
  });
  let source = fs.readFileSync(path.join(root, "static", `${name}.js`), "utf8");
  source = source.replace(/^import .*;\n/, "");
  source = source.replace(name === "admin" ? "\nloadApplication();" : "\nload();", "");
  vm.runInContext(source, context, {filename: `${name}.js`});
  return {clock, context, document, documentEvents, windowEvents, elements, navigations};
}

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {get: () => "application/json"},
    text: async () => JSON.stringify(body),
    json: async () => body,
    blob: async () => ({}),
  };
}

async function testAdminReset() {
  const requests = [];
  const successful = harness("admin", {
    async fetch(route) {
      requests.push(route);
      if (route === "api/admin/connection/reset") {
        return jsonResponse(202, {grants_revoked: 1, remote_failures: []});
      }
      if (route.startsWith("health?transition=")) {
        return jsonResponse(200, {status: "setup_required"});
      }
      throw new Error(`Unexpected request: ${route}`);
    },
  });
  successful.elements.get("reset-confirmation").value = "RESET";
  await vm.runInContext("resetLayerVConnection()", successful.context);
  assert.equal(successful.navigations.length, 1);
  const destination = new URL(successful.navigations[0]);
  assert.equal(destination.pathname, "/api/hassio_ingress/session/admin");
  assert.ok(destination.searchParams.has("reset"));
  assert.ok(requests.some((route) => route.startsWith("health?transition=")));

  const interrupted = harness("admin", {
    async fetch(route) {
      if (route === "api/admin/connection/reset") throw new Error("Upstream switched");
      return jsonResponse(200, {status: "setup_required"});
    },
  });
  interrupted.elements.get("reset-confirmation").value = "RESET";
  await vm.runInContext("resetLayerVConnection()", interrupted.context);
  assert.equal(interrupted.navigations.length, 1);

  let healthRequests = 0;
  const failed = harness("admin", {
    async fetch(route) {
      if (route.startsWith("health")) healthRequests++;
      return jsonResponse(400, {error: "Reset rejected"});
    },
  });
  failed.elements.get("reset-confirmation").value = "RESET";
  await vm.runInContext("resetLayerVConnection()", failed.context);
  assert.equal(failed.navigations.length, 0);
  assert.equal(healthRequests, 0);
  assert.match(failed.elements.get("reset-status").textContent, /Reset rejected/);
}

async function testGuestVisibility() {
  const stateRequests = [];
  const cameraRequests = [];
  const fixture = harness("access", {
    async fetchPage() {
      stateRequests.push(fixture.clock.now);
      return jsonResponse(200, {resources: [], title: "Fixture"});
    },
    async cameraFrame() {
      cameraRequests.push(fixture.clock.now);
      return jsonResponse(200, {});
    },
  });
  vm.runInContext("currentPageId = 'fixture'; render = () => {};", fixture.context);
  await vm.runInContext("poll()", fixture.context);
  assert.deepEqual(fixture.clock.delays(), [3000]);
  await fixture.clock.advance(3000);
  assert.equal(stateRequests.length, 2);

  const card = new Element();
  vm.runInContext(
    "renderCameraFrame({id: 'fixture'}, {id: 'camera', name: 'Camera', domain: 'camera', camera_refresh_interval: 15}, cameraCard)",
    Object.assign(fixture.context, {cameraCard: card, URL: {
      ...URL, createObjectURL: () => "blob:frame", revokeObjectURL() {},
    }}),
  );
  await settle();
  assert.equal(cameraRequests.length, 1);
  assert.deepEqual(fixture.clock.delays(), [3000, 15000]);

  fixture.document.hidden = true;
  fixture.documentEvents.get("visibilitychange")();
  assert.deepEqual(fixture.clock.delays(), []);
  await vm.runInContext("poll()", fixture.context);
  fixture.windowEvents.get("online")();
  assert.deepEqual(fixture.clock.delays(), []);
  await fixture.clock.advance(120000);
  assert.equal(stateRequests.length, 2);
  assert.equal(cameraRequests.length, 1);

  fixture.document.hidden = false;
  fixture.documentEvents.get("visibilitychange")();
  fixture.documentEvents.get("visibilitychange")();
  fixture.windowEvents.get("focus")();
  await settle();
  assert.equal(stateRequests.length, 3);
  assert.deepEqual(fixture.clock.delays(), [3000, 15000]);
  await fixture.clock.advance(3000);
  assert.equal(stateRequests.length, 4);
  await fixture.clock.advance(12000);
  assert.equal(cameraRequests.length, 2);
  assert.deepEqual(fixture.clock.delays(), [3000, 15000]);

  const beforeTransitions = stateRequests.length;
  fixture.document.hidden = true;
  fixture.documentEvents.get("visibilitychange")();
  fixture.document.hidden = false;
  fixture.documentEvents.get("visibilitychange")();
  fixture.document.hidden = true;
  fixture.documentEvents.get("visibilitychange")();
  await settle();
  assert.equal(stateRequests.length, beforeTransitions + 1);
  assert.deepEqual(fixture.clock.delays(), []);

  fixture.document.hidden = false;
  fixture.documentEvents.get("visibilitychange")();
  fixture.documentEvents.get("visibilitychange")();
  await settle();
  assert.equal(stateRequests.length, beforeTransitions + 2);
  assert.deepEqual(fixture.clock.delays(), [3000, 15000]);
}

async function testRevocationOnReturn() {
  let requests = 0;
  const fixture = harness("access", {
    async fetchPage() {
      requests++;
      return requests === 1
        ? jsonResponse(200, {resources: [], title: "Fixture"})
        : jsonResponse(410, {error: "Expired"});
    },
  });
  vm.runInContext("currentPageId = 'fixture'; render = () => {};", fixture.context);
  await vm.runInContext("poll()", fixture.context);
  fixture.document.hidden = true;
  fixture.documentEvents.get("visibilitychange")();
  await fixture.clock.advance(120000);
  assert.equal(requests, 1);
  assert.deepEqual(fixture.clock.delays(), []);
  fixture.document.hidden = false;
  fixture.documentEvents.get("visibilitychange")();
  await settle();
  assert.equal(requests, 2);
  assert.match(fixture.elements.get("status").textContent, /expired or been revoked/);
  assert.deepEqual(fixture.clock.delays(), []);
}

async function testUnavailableOnReturn() {
  let requests = 0;
  const fixture = harness("access", {
    async fetchPage() {
      requests++;
      return requests === 2
        ? jsonResponse(503, {error: "Connection unavailable"})
        : jsonResponse(200, {resources: [], title: "Fixture"});
    },
  });
  vm.runInContext("currentPageId = 'fixture'; render = () => {};", fixture.context);
  await vm.runInContext("poll()", fixture.context);
  fixture.document.hidden = true;
  fixture.documentEvents.get("visibilitychange")();
  await fixture.clock.advance(120000);
  assert.equal(requests, 1);
  fixture.document.hidden = false;
  fixture.documentEvents.get("visibilitychange")();
  await settle();
  assert.equal(requests, 2);
  assert.match(fixture.elements.get("status").textContent, /Connection unavailable/);
  assert.deepEqual(fixture.clock.delays(), [6000]);
  await fixture.clock.advance(6000);
  assert.equal(requests, 3);
  assert.deepEqual(fixture.clock.delays(), [3000]);
}

async function testVerificationPause() {
  let requests = 0;
  const fixture = harness("access", {
    async fetchPage() {
      requests++;
      return jsonResponse(200, {resources: [], title: "Fixture"});
    },
  });
  vm.runInContext("currentPageId = 'fixture'; render = () => {};", fixture.context);
  await vm.runInContext("poll()", fixture.context);
  vm.runInContext("verificationPending = true", fixture.context);
  fixture.document.hidden = true;
  fixture.documentEvents.get("visibilitychange")();
  await fixture.clock.advance(120000);
  fixture.document.hidden = false;
  fixture.documentEvents.get("visibilitychange")();
  await settle();
  assert.equal(requests, 1);
  assert.deepEqual(fixture.clock.delays(), []);
}

async function testVerificationRecovery() {
  for (const stateStatus of [200, 401]) {
    let reads = 0;
    const fixture = harness("access", {
      async verification() { return jsonResponse(200, {status: "session_ready"}); },
      async fetchPage() {
        if (++reads === 1) throw new Error("Connection timed out.");
        return jsonResponse(stateStatus, {resources: [], title: "Fixture", error: "Access ended"});
      },
    });
    vm.runInContext("currentPageId = 'fixture'; verificationPending = true; render = () => {};", fixture.context);
    fixture.elements.get("verification-dialog").open = true;
    fixture.elements.get("verification-code").value = "123456";
    await fixture.elements.get("verification-form").listeners.get("submit")({preventDefault() {}});
    assert.equal(fixture.elements.get("verification-dialog").open, false);
    assert.match(fixture.elements.get("status").textContent, /Connection timed out.*Controls are unavailable/);
    assert.equal(vm.runInContext("connectionUnavailable", fixture.context), true);
    assert.deepEqual(fixture.clock.delays(), [6000]);
    await fixture.clock.advance(6000);
    assert.equal(reads, 2);
    assert.equal(vm.runInContext("accessEnded", fixture.context), stateStatus === 401);
    assert.deepEqual(fixture.clock.delays(), stateStatus === 401 ? [] : [3000]);
  }
  const denied = harness("access", {
    async verification() { return jsonResponse(401, {error: "Invalid code"}); },
    async fetchPage() { throw new Error("Must remain gated"); },
  });
  vm.runInContext("currentPageId = 'fixture'; verificationPending = true;", denied.context);
  denied.elements.get("verification-dialog").open = true;
  denied.elements.get("verification-code").value = "123456";
  await denied.elements.get("verification-form").listeners.get("submit")({preventDefault() {}});
  assert.equal(denied.elements.get("verification-dialog").open, true);
  assert.equal(vm.runInContext("verificationPending", denied.context), true);
  assert.deepEqual(denied.clock.delays(), []);
}

(async () => {
  await testAdminReset();
  await testGuestVisibility();
  await testRevocationOnReturn();
  await testUnavailableOnReturn();
  await testVerificationPause();
  await testVerificationRecovery();
  console.log("Frontend runtime reset and visibility tests passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
