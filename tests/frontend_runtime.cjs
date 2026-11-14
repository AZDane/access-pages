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
    const classes = new Set();
    this.classList = {
      add(...names) { names.forEach(name => classes.add(name)); },
      remove(...names) { names.forEach(name => classes.delete(name)); },
      toggle(name, force = !classes.has(name)) {
        if (force) classes.add(name);
        else classes.delete(name);
        return force;
      },
      contains(name) { return classes.has(name); },
    };
    this.value = "";
    this.open = false;
  }
  addEventListener(name, callback) { this.listeners.set(name, callback); }
  checkValidity() { return this.value.includes("@"); }
  appendChild(child) { this.children.push(child); return child; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes.set(name, value); }
  getAttribute(name) { return name === "src" ? this.src || null : this.attributes.get(name) || null; }
  removeAttribute(name) { this.attributes.delete(name); if (name === "src") this.src = ""; }
  insertAdjacentElement(_position, element) { this.adjacent = element; }
  remove() {}
  close() { this.open = false; }
  showModal() { this.open = true; }
  focus() {}
  scrollIntoView() {}
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
      if (!elements.has(id)) { const element = new Element(); element.id = id; elements.set(id, element); }
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
  vm.runInContext("render = () => renderCameraFrame({id: 'fixture'}, {id: 'camera', name: 'Camera', domain: 'camera', camera_refresh_interval: 15}, cameraCard);", fixture.context);
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
  assert.equal(cameraRequests.length, 3);
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

async function assertBodyTimeoutKeepsRequestId() {
  const clock = new Clock();
  let calls = 0;
  const context = vm.createContext({
    AbortController, URLSearchParams, Response,
    setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout,
    window: {fetch: async (_url, options) => {
      calls++;
      return {headers: new Headers({"X-Access-Pages-Request-ID": "a".repeat(32)}),
        arrayBuffer: () => new Promise((_resolve, reject) => options.signal.addEventListener("abort", () => reject(new Error("aborted"))))};
    }},
  });
  const source = fs.readFileSync(path.join(root, "static/access-api.js"), "utf8").replaceAll("export ", "");
  vm.runInContext(source, context);
  const pending = vm.runInContext('boundedRequest("synthetic")', context);
  const caught = pending.catch(error => error);
  await settle();
  await clock.advance(10000);
  const error = await caught;
  assert.equal(error.name, "Error");
  assert.equal(error.requestId, "a".repeat(32));
  assert.match(error.message, /timed out/);
  assert.equal(calls, 1, "A timed out action must never be replayed");
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

function prepareGuest(api) {
  const fixture = harness("access", api);
  vm.runInContext("currentPageId = 'fixture'; render = page => { title.textContent = page.title; };", fixture.context);
  fixture.context.actionButton = new Element();
  fixture.context.succeeded = 0;
  return fixture;
}

const executeAction = "runAction('fixture', 'light', 'turn_on', actionButton, {}, {onSuccess: () => succeeded++})";

async function testActionFreshState() {
  for (const status of [200, 401, 403, 410, 502]) {
    const refreshed = deferred();
    let reads = 0, writes = 0;
    const fixture = prepareGuest({
      async fetchPage() {
        return ++reads === 1 ? jsonResponse(200, {title: "Before"}) : refreshed.promise;
      },
      async runAction() { writes++; return jsonResponse(200, {success: true}); },
      async verification() { return jsonResponse(200, {sent: true}); },
    });
    await vm.runInContext("fetchPage()", fixture.context);
    const action = vm.runInContext(executeAction, fixture.context);
    await settle();
    assert.equal(fixture.context.succeeded, 0, "Acknowledgement alone cannot finalize action UI");
    assert.equal(vm.runInContext("commandInProgress", fixture.context), true);
    refreshed.resolve(jsonResponse(status, {title: "After", verification_required: status === 403}));
    await action;
    assert.equal(fixture.context.succeeded, status === 200 ? 1 : 0);
    assert.equal(vm.runInContext("controlsFresh", fixture.context), status === 200);
    await fixture.clock.advance(6000);
    assert.equal(writes, 1, "Recovery only reads; never replays a command");
  }
}

async function testPrecommandReadCannotFinalizeAction() {
  const old = deferred(), fresh = deferred();
  let reads = 0;
  const fixture = prepareGuest({
    async fetchPage() {
      reads++;
      return reads === 1 ? jsonResponse(200, {title: "Initial"}) : reads === 2 ? old.promise : fresh.promise;
    },
    async runAction() { return jsonResponse(200, {}); },
  });
  await vm.runInContext("fetchPage()", fixture.context);
  const obsolete = vm.runInContext("poll()", fixture.context);
  const action = vm.runInContext(executeAction, fixture.context);
  await settle();
  assert.equal(reads, 3, "Post-action read does not wait for a pre-action read");
  old.resolve(jsonResponse(200, {title: "Old"}));
  await obsolete;
  assert.equal(fixture.context.succeeded, 0);
  fresh.resolve(jsonResponse(200, {title: "Fresh"}));
  await action;
  assert.equal(fixture.context.succeeded, 1);
  assert.equal(fixture.elements.get("title").textContent, "Fresh");
}

async function testObsoleteResponses() {
  for (const transition of ["offline", "background", "bfcache"]) {
    for (const outcome of [200, 410, "error"]) {
      const old = deferred(), fresh = deferred();
      let reads = 0, writes = 0;
      const fixture = prepareGuest({
        async fetchPage() {
          reads++;
          return reads === 1 ? jsonResponse(200, {title: "Initial"}) : reads === 2 ? old.promise : fresh.promise;
        },
        async runAction() { writes++; return jsonResponse(200, {}); },
      });
      await vm.runInContext("fetchPage()", fixture.context);
      const obsolete = vm.runInContext("poll()", fixture.context);
      await settle();
      if (transition === "offline") {
        fixture.context.navigator.onLine = false;
        fixture.windowEvents.get("offline")();
        fixture.context.navigator.onLine = true;
        fixture.windowEvents.get("online")();
      } else if (transition === "background") {
        fixture.document.hidden = true;
        fixture.documentEvents.get("visibilitychange")();
        fixture.document.hidden = false;
        fixture.documentEvents.get("visibilitychange")();
      } else fixture.windowEvents.get("pageshow")({persisted: true});
      await vm.runInContext(executeAction, fixture.context);
      assert.equal(writes, 0, "Controls stay gated until a new authorized read");
      assert.equal(reads, 3, "An obsolete request cannot block a fresh read");
      fresh.resolve(jsonResponse(200, {title: "Fresh"}));
      await settle();
      if (outcome === "error") old.reject(new Error("old connection failure"));
      else old.resolve(jsonResponse(outcome, {title: "Obsolete"}));
      await obsolete;
      assert.equal(fixture.elements.get("title").textContent, "Fresh");
      assert.equal(vm.runInContext("accessEnded || connectionUnavailable", fixture.context), false);
      assert.equal(vm.runInContext("controlsFresh", fixture.context), true);
    }
  }
}

async function testInterruptedActionsAndCamera() {
  const acknowledged = deferred();
  let writes = 0;
  const fixture = prepareGuest({
    async fetchPage() { return jsonResponse(200, {title: "Current"}); },
    async runAction() { writes++; return acknowledged.promise; },
  });
  await vm.runInContext("fetchPage()", fixture.context);
  const action = vm.runInContext(executeAction, fixture.context);
  await settle();
  fixture.elements.get("resources").appendChild(new Element());
  vm.runInContext("endAccess()", fixture.context);
  assert.equal(fixture.elements.get("resources").children.length, 0);
  acknowledged.resolve(jsonResponse(200, {}));
  await action;
  assert.equal(fixture.context.succeeded, 0);
  assert.match(fixture.elements.get("status").textContent, /expired or been revoked/);
  assert.equal(writes, 1);

  const location = deferred();
  const waiting = prepareGuest({async fetchPage() { return jsonResponse(200, {}); },
    async runAction() { throw new Error("An obsolete location prompt must not send a command"); }});
  waiting.context.locationResult = location.promise;
  await vm.runInContext("fetchPage(); actionProximity = () => locationResult;", waiting.context);
  const unsent = vm.runInContext(executeAction, waiting.context);
  waiting.document.hidden = true;
  waiting.documentEvents.get("visibilitychange")();
  location.resolve(null);
  await unsent;
  assert.equal(waiting.context.succeeded, 0);

  const image = deferred();
  const camera = prepareGuest({async fetchPage() { return jsonResponse(200, {}); },
    async cameraFrame() { return image.promise; }});
  await vm.runInContext("fetchPage()", camera.context);
  camera.context.card = new Element();
  vm.runInContext("renderCameraFrame({id: 'fixture'}, {id: 'camera', name: 'Camera', domain: 'camera'}, card)", camera.context);
  camera.windowEvents.get("offline")();
  camera.windowEvents.get("online")();
  await settle();
  image.resolve(jsonResponse(410, {}));
  await settle();
  assert.equal(vm.runInContext("accessEnded", camera.context), false, "Obsolete camera failure cannot end renewed access");
}

async function testInvitationAndRevocationFeedback() {
  let writes = 0;
  const fixture = harness("admin", {async fetch() { writes++; return jsonResponse(400, {error: "Rejected invitation"}); }});
  vm.runInContext("currentPage = {id: 'fixture'}; editingExisting = true; layerVApiConfigured = true; selectedLifetime = () => '1h';", fixture.context);
  fixture.elements.get("qurl-label").value = "Guest";
  fixture.elements.get("activity-notifications").checked = true;
  await vm.runInContext("generateQurl()", fixture.context);
  assert.equal(!!fixture.elements.get("generate-qurl").disabled, false);
  assert.match(fixture.elements.get("user-dialog-status").textContent, /notification target/);
  assert.equal(writes, 0);
  fixture.elements.get("activity-notifications").checked = false;
  fixture.elements.get("send-invitation").checked = true;
  await vm.runInContext("generateQurl()", fixture.context);
  assert.match(fixture.elements.get("user-dialog-status").textContent, /valid email/);
  fixture.elements.get("verification-email").value = "guest@example.invalid";
  await vm.runInContext("generateQurl()", fixture.context);
  assert.equal(writes, 1);
  assert.equal(fixture.elements.get("generate-qurl").disabled, false);
  assert.match(fixture.elements.get("user-dialog-status").textContent, /Rejected invitation/);

  for (const [status, pending, failures, message] of [
    [200, 1, [], /locally.*queued/], [502, 0, [{error: "Missing qURL ID"}], /locally.*not confirmed/], [200, 0, [], /confirmed/],
  ]) {
    const admin = harness("admin", {async fetch() { return jsonResponse(status, {
      local_access_revoked: true, revoked_count: 1, remote_revocation_pending_count: pending, remote_failures: failures,
    }); }});
    vm.runInContext("currentPage = {id: 'fixture', access_grants: [{}]}; editingExisting = true; confirmAction = async () => true; loadPages = async () => {}; loadGuestActivitySummaries = async () => {}; renderAccessGrants = () => {};", admin.context);
    await vm.runInContext("revokeAllQurls()", admin.context);
    assert.equal(vm.runInContext("currentPage.access_grants.length", admin.context), 0);
    assert.match(admin.elements.get("status").textContent, message);
  }
}

async function testVerificationOptionAvailability() {
  let payload;
  const fixture = harness("admin", {async fetch(route, options) {
    payload = JSON.parse(options.body);
    return jsonResponse(400, {error: "Rejected invitation"});
  }});
  const invitation = fixture.elements.get("send-invitation");
  const verification = fixture.elements.get("verification-required");
  const emailField = fixture.elements.get("verification-email-field");
  vm.runInContext("scopedGuestSupported = true; openUserDialog();", fixture.context);
  const option = fixture.elements.get("verification-option");
  assert.equal(option.classList.contains("hidden"), true);
  assert.equal(verification.disabled, true);

  vm.runInContext("emailConfigured = true; openUserDialog();", fixture.context);
  assert.equal(invitation.checked, false);
  assert.equal(option.classList.contains("hidden"), false);
  assert.equal(verification.disabled, false);
  assert.equal(emailField.classList.contains("hidden"), true);
  verification.checked = true;
  verification.listeners.get("change")();
  assert.equal(verification.checked, true);
  assert.equal(emailField.classList.contains("hidden"), false);
  invitation.checked = true;
  invitation.listeners.get("change")();
  invitation.checked = false;
  invitation.listeners.get("change")();
  assert.equal(verification.checked, true, "Invitation toggle must preserve verification");
  assert.equal(emailField.classList.contains("hidden"), false);

  vm.runInContext("currentPage = {id: 'fixture'}; editingExisting = true; layerVApiConfigured = true; selectedLifetime = () => '1h';", fixture.context);
  fixture.elements.get("qurl-label").value = "Guest";
  await vm.runInContext("generateQurl()", fixture.context);
  assert.match(fixture.elements.get("user-dialog-status").textContent, /valid email/);
  assert.equal(payload, undefined);
  fixture.elements.get("verification-email").value = "guest@example.test";
  await vm.runInContext("generateQurl()", fixture.context);
  assert.equal(payload.verification_required, true);
  assert.equal(payload.verification_email, "guest@example.test");
  assert.equal(payload.send_invitation, true);

  verification.checked = false;
  verification.listeners.get("change")();
  assert.equal(emailField.classList.contains("hidden"), true);
  assert.equal(option.classList.contains("hidden"), false);
  invitation.checked = true;
  invitation.listeners.get("change")();
  assert.equal(emailField.classList.contains("hidden"), false);
  vm.runInContext("scopedGuestSupported = false; configureGuestOptions();", fixture.context);
  assert.equal(option.classList.contains("hidden"), false);
  assert.equal(verification.disabled, true);
  verification.checked = true;
  vm.runInContext("emailConfigured = false; configureGuestOptions();", fixture.context);
  assert.equal(option.classList.contains("hidden"), true);
  assert.equal(verification.checked, false);
  assert.equal(invitation.checked, false);
  assert.equal(emailField.classList.contains("hidden"), true);
}

function descendants(element) {
  return [element, ...element.children.flatMap(descendants)];
}

async function testGuestDraftAndValidation() {
  let failSave = false, previewEmpty = false, holdSave = null, requests = 0;
  const fixture = harness("admin", {async fetch(route, options) {
    requests++;
    const payload = JSON.parse(options.body);
    if (payload.action === "preview") return jsonResponse(200, {upcoming: previewEmpty ? [] : [{start: 4102444800, end: 4102455600}]});
    if (holdSave) await holdSave;
    if (failSave) return jsonResponse(503, {error: "Storage unavailable"});
    if (route.endsWith("/qurls")) return jsonResponse(200, {grant: {id: "test", qurl_link: "synthetic", expires_at: "2099-01-01T12:00:00Z"}});
    assert.equal(payload.action, "save");
    return jsonResponse(200, {success: true});
  }});
  const e = id => fixture.document.getElementById(id);
  const scheduleIds = ["schedule-name", "schedule-email", "schedule-kind", "schedule-date", "schedule-start", "schedule-end", "schedule-guest"];
  const manualIds = ["qurl-label", "verification-email", "send-invitation", "activity-notifications"];
  let targets = [], events = [];
  fixture.document.querySelectorAll = selector => {
    if (selector === "#schedule-dialog input, #schedule-dialog select") return scheduleIds.map(e);
    if (selector === "#user-dialog input, #user-dialog select") return manualIds.map(e);
    if (selector === '#schedule-dialog button') return [e("save-schedule"), e("close-schedule")];
    if (selector === 'input[name="schedule-target"]:checked') return targets;
    if (selector === 'input[name="schedule-event"]:checked') return events;
    return [];
  };
  vm.runInContext("currentPage = {id: 'fixture', access_grants: []}; editingExisting = true; layerVApiConfigured = true; loadSchedules = async () => {};", fixture.context);
  let confirms = 0, discard = false;
  fixture.context.confirmAction = async () => { confirms++; return discard; };
  const open = () => vm.runInContext("openSchedule()", fixture.context);
  const close = () => e("close-schedule").listeners.get("click")();
  open(); await close(); assert.equal(confirms, 0, "Untouched form closes silently");
  open(); e("schedule-name").value = "Edited"; await close();
  assert.equal(confirms, 1); assert.equal(e("schedule-dialog").open, true);
  e("schedule-name").value = ""; await close();
  assert.equal(confirms, 1, "Reverting an edit is clean");
  open(); e("schedule-name").value = "Visitor"; e("schedule-email").value = "guest@example.invalid"; e("schedule-date").value = "2099-01-01";
  e("schedule-first").value = "2099-12-31"; e("schedule-last").value = "2099-01-01";
  assert.equal(vm.runInContext("scheduleFields().first_date", fixture.context), "", "One-time dates ignore hidden recurrence limits");
  targets = [{value: "email"}];
  const preview = () => e("preview-schedule").listeners.get("click")();
  await preview();
  assert.equal(requests, 0, "Incomplete alerts are caught before the request");
  assert.match(e("schedule-form-status").className, /error/);
  assert.match(e("schedule-form-status").textContent, /at least one activity/);
  assert.equal(e("schedule-alerts").getAttribute("aria-invalid"), "true");
  events = [{value: "initial_login"}];
  await preview(); await close(); assert.equal(confirms, 2, "A preview is not a successful save");
  previewEmpty = true; await preview();
  assert.equal(e("schedule-date").getAttribute("aria-invalid"), "true");
  previewEmpty = false;
  const submit = () => e("schedule-form").listeners.get("submit")({preventDefault() {}});
  failSave = true; await submit(); await close();
  assert.equal(confirms, 3, "Failed saves retain edits");
  assert.equal(e("schedule-dialog").open, true);
  assert.match(e("schedule-form-status").textContent, /Storage unavailable/);
  failSave = false;
  let release;
  holdSave = new Promise(resolve => { release = resolve; });
  const pending = submit(); await settle(); await close();
  assert.equal(confirms, 3, "Saving cannot be dismissed mid-request");
  assert.equal(e("close-schedule").disabled, true);
  release(); await pending; holdSave = null;
  assert.equal(e("schedule-dialog").open, false);
  await close(); assert.equal(confirms, 3, "Successful saves clear the draft");
  let finishRefresh;
  fixture.context.refreshPending = new Promise(resolve => { finishRefresh = resolve; });
  vm.runInContext("loadSchedules = () => refreshPending;", fixture.context);
  open(); e("schedule-name").value = "Another guest"; e("schedule-date").value = "2099-01-01";
  const refreshing = submit(); await settle();
  assert.equal(e("schedule-dialog").open, false);
  open(); assert.equal(Boolean(e("close-schedule").disabled), false, "Next dialog is usable during background refresh");
  finishRefresh(); await refreshing;
  e("schedule-name").value = "Unsaved";
  let prevented = false;
  e("schedule-dialog").listeners.get("cancel")({preventDefault() { prevented = true; }}); await settle();
  assert.equal(prevented, true); assert.equal(e("schedule-dialog").open, true);
  discard = true;
  e("schedule-dialog").listeners.get("click")({target: e("schedule-dialog")}); await settle();
  assert.equal(e("schedule-dialog").open, false, "Confirmed backdrop dismissal closes");
  discard = false;
  vm.runInContext("openSchedule({id: 'existing', definition: {...scheduleFields(), notifications: {targets: [], events: []}}})", fixture.context);
  const beforeEdit = confirms;
  await close(); assert.equal(confirms, beforeEdit, "Untouched edit dialog closes silently");
  vm.runInContext("openSchedule({id: 'existing', definition: {...scheduleFields(), notifications: {targets: [], events: []}}})", fixture.context);
  e("schedule-name").value = "Changed existing guest";
  await close(); assert.equal(confirms, beforeEdit + 1, "Changed edit dialog warns");
  discard = true; await close(); discard = false;
  vm.runInContext("openUserDialog()", fixture.context);
  await e("close-user-dialog").listeners.get("click")();
  const before = confirms;
  vm.runInContext("openUserDialog()", fixture.context);
  e("qurl-label").value = "Visitor";
  await e("close-user-dialog").listeners.get("click")();
  assert.equal(confirms, before + 1); assert.equal(e("user-dialog").open, true);
  vm.runInContext("selectedLifetime = () => '1h'; buildSharePanel = () => document.createElement('div'); finishedSharingButton = () => document.createElement('button'); loadPages = async () => {}; loadGuestActivitySummaries = async () => {}; renderAccessGrants = () => {}; window.requestAnimationFrame = callback => callback();", fixture.context);
  failSave = true; await vm.runInContext("generateQurl()", fixture.context);
  await e("close-user-dialog").listeners.get("click")();
  assert.equal(confirms, before + 2, "Failed immediate invitation retains the draft");
  failSave = false; await vm.runInContext("generateQurl()", fixture.context);
  await e("close-user-dialog").listeners.get("click")();
  assert.equal(confirms, before + 2, "Created invitation clears draft protection");
  assert.equal(e("user-dialog").open, false);
}

async function testScheduledGuestWorkflow() {
  let smtp = false;
  const timelineRequests = [];
  const revocations = [];
  const rows = {guests: [{id: "guest_test", label: "Visitor", email: "guest@example.test", needs_attention: true}], schedules: [{id: "schedule_test", guest_id: "guest_test", status: "enabled", definition: {label: "Visitor", email: "guest@example.test", kind: "weekly", timezone: "America/Phoenix", weekdays: [5,6], start_time: "09:00", end_time: "12:00"}, upcoming: [{start: 1794672000, end: 1794682800}]}], scheduled_grants: {grant_current: "guest_test"}, active_invitations: [{id: "grant_current", label: "Visitor", expires_at: "2099-01-01T00:00:00Z"}], supported: true, timezone: "America/Phoenix"};
  const fixture = harness("admin", {async fetch(route, options = {}) {
    assert.match(route, /pages\/fixture\/schedules/);
    if (options.method === "POST") {
      const payload = JSON.parse(options.body);
      if (payload.action === "timeline") {
        timelineRequests.push(payload);
        return jsonResponse(200, {events: [{type: "delivery", at: 1794672000, start: 1794672000, end: 1794682800, timezone: "America/Phoenix", occurrence_id: "occ_fixture", state: "accepted", accepted_at: 1794672000}], next_cursor: payload.cursor ? null : {at: 1794672000, key: "delivery:occ_fixture"}});
      }
      if (payload.action === "revoke_guest") {
        assert.equal(payload.guest_id, "guest_test");
        assert.ok(route.endsWith("/schedules"), "Guest revoke must not target an editing schedule");
        revocations.push(payload); rows.schedules[0].status = "revoked"; rows.active_invitations = [];
        return jsonResponse(200, {success: true});
      }
      if (payload.action === "resume") {
        rows.schedules[0].status = "enabled";
        return jsonResponse(200, {success: true});
      }
      assert.equal(payload.action, "pause_all");
      if (rows.schedules[0].status !== "revoked") rows.schedules[0].status = "paused";
      return jsonResponse(200, {success: true});
    }
    return jsonResponse(200, {...rows, smtp_configured: smtp});
  }});
  vm.runInContext(`Intl.DateTimeFormat = function () { return {
    resolvedOptions: () => ({timeZone: "America/Los_Angeles"}), format: () => "local time"
  }; };`, fixture.context);
  rows.timezones = ["America/Phoenix", "America/Los_Angeles", "Europe/London", "UTC"];
  vm.runInContext("currentPage = {id: 'fixture'}; confirmAction = async () => true;", fixture.context);
  await vm.runInContext("loadSchedules()", fixture.context);
  assert.equal(fixture.elements.get("add-schedule").disabled, true);
  assert.match(fixture.elements.get("schedule-availability").textContent, /Configure SMTP/);
  await fixture.elements.get("add-user").listeners.get("click")();
  assert.equal(fixture.elements.get("guest-choice-dialog").open, true);
  assert.equal(fixture.elements.get("user-dialog").open, false);
  assert.equal(fixture.elements.get("add-schedule").disabled, true);
  assert.match(fixture.elements.get("guest-schedule-help").textContent, /Configure SMTP/);
  fixture.elements.get("add-guest-now").listeners.get("click")();
  assert.equal(fixture.elements.get("guest-choice-dialog").open, false);
  assert.equal(fixture.elements.get("user-dialog").open, true);
  fixture.elements.get("close-user-dialog").listeners.get("click")();
  assert.ok(descendants(fixture.elements.get("schedule-list")).some(e => e.textContent?.includes("America/Phoenix")));
  smtp = true;
  await vm.runInContext("loadSchedules()", fixture.context);
  assert.equal(fixture.elements.get("add-schedule").disabled, false);
  let card = fixture.elements.get("schedule-list").children[0];
  const expandButton = card => descendants(card).find(e => e.attributes.get("aria-controls"));
  assert.equal(expandButton(card).getAttribute("aria-expanded"), "false");
  assert.equal(card.children[1].classList.contains("hidden"), true);
  assert.ok(descendants(card.children[0]).some(e => e.textContent === "Revoke guest"));
  assert.ok(descendants(card).some(e => e.textContent === "Revoke this invitation"));
  assert.equal(timelineRequests.length, 0, "Collapsed cards must not load history");
  assert.ok(descendants(card).some(e => e.textContent?.includes("Needs attention")));
  expandButton(card).listeners.get("click")(); await settle();
  assert.equal(expandButton(card).getAttribute("aria-expanded"), "true");
  assert.equal(timelineRequests.length, 1);
  const more = descendants(card).find(e => e.textContent === "Load older entries");
  more.listeners.get("click")(); await settle();
  assert.deepEqual(timelineRequests[1].cursor, {at: 1794672000, key: "delivery:occ_fixture"});
  assert.equal(more.classList.contains("hidden"), true);
  descendants(card).find(e => e.textContent === "Show this access window").listeners.get("click")(); await settle();
  assert.equal(timelineRequests.at(-1).occurrence_id, "occ_fixture");
  descendants(card).find(e => e.textContent === "Show all access windows").listeners.get("click")(); await settle();
  assert.equal(timelineRequests.at(-1).occurrence_id, null);
  await vm.runInContext("loadSchedules()", fixture.context);
  card = fixture.elements.get("schedule-list").children[0];
  assert.equal(expandButton(card).getAttribute("aria-expanded"), "true", "Refresh preserves expanded cards");
  expandButton(card).listeners.get("click")(); await settle();
  const revoke = descendants(card.children[0]).find(e => e.textContent === "Revoke guest");
  vm.runInContext("confirmAction = async () => false", fixture.context);
  revoke.listeners.get("click")(); await settle();
  assert.equal(revocations.length, 0);
  vm.runInContext("confirmAction = async message => { if (!message.includes('all current access') || !message.includes('all future schedules')) throw Error('Missing revoke scope'); return true; }; editingSchedule = 'unrelated';", fixture.context);
  revoke.listeners.get("click")(); await settle();
  assert.equal(revocations.length, 1);
  assert.equal(fixture.elements.get("schedule-list").children.length, 0);
  card = fixture.elements.get("ended-scheduled-list").children[0];
  assert.equal(expandButton(card).getAttribute("aria-expanded"), "false", "Revocation does not expand a collapsed card");
  assert.equal(fixture.elements.get("revoked-count").textContent, "1");
  assert.ok(descendants(card).some(e => e.textContent?.includes("Scheduled · Revoked")));
  assert.ok(!descendants(card.children[0]).some(e => e.textContent === "Revoke guest"));
  await vm.runInContext("loadSchedules()", fixture.context);
  assert.equal(fixture.elements.get("ended-scheduled-list").children.length, 1, "Revoked placement survives refresh");
  card = fixture.elements.get("ended-scheduled-list").children[0];
  expandButton(card).listeners.get("click")(); await settle();
  descendants(card).find(e => e.textContent === "Resume").listeners.get("click")(); await settle();
  assert.equal(fixture.elements.get("ended-scheduled-list").children.length, 0);
  assert.equal(fixture.elements.get("schedule-list").children.length, 1, "Explicit resume returns guest to scheduled list");
  vm.runInContext("confirmAction = async () => true; editingSchedule = null;", fixture.context);
  await fixture.elements.get("add-user").listeners.get("click")();
  fixture.elements.get("add-schedule").listeners.get("click")();
  assert.equal(fixture.elements.get("guest-choice-dialog").open, false);
  assert.equal(fixture.elements.get("schedule-dialog").open, true);
  assert.equal(fixture.elements.get("schedule-verification").checked, true);
  assert.equal(fixture.elements.get("schedule-single-use").checked, false);
  assert.equal(fixture.elements.get("schedule-timezone").value, "America/Los_Angeles");
  assert.ok(fixture.elements.get("schedule-timezone").children.some(option => option.value === "Europe/London"));
  assert.match(fixture.elements.get("schedule-timezone-help").textContent, /America\/Los_Angeles/);
  const saved = JSON.parse(vm.runInContext("JSON.stringify(scheduleFields())", fixture.context));
  saved.timezone = "Europe/London";
  fixture.context.savedSchedule = {id: "saved", guest_id: "guest_test", definition: saved};
  vm.runInContext("openSchedule(savedSchedule)", fixture.context);
  assert.equal(fixture.elements.get("schedule-timezone").value, "Europe/London");
  vm.runInContext("openSchedule(savedSchedule, true)", fixture.context);
  assert.equal(fixture.elements.get("schedule-timezone").value, "Europe/London");
  assert.equal(fixture.elements.get("schedule-guest").value, "guest_test");
  assert.equal(fixture.elements.get("schedule-email").readOnly, true);
  fixture.elements.get("schedule-guest").value = "";
  fixture.elements.get("schedule-guest").listeners.get("change")();
  assert.equal(fixture.elements.get("schedule-email").readOnly, false);
  vm.runInContext("Intl.DateTimeFormat = () => { throw new Error('unavailable'); }; openSchedule();", fixture.context);
  assert.equal(fixture.elements.get("schedule-timezone").value, "America/Phoenix");
  for (const id of ["schedule-date", "schedule-first", "schedule-last"]) {
    const field = fixture.elements.get(id);
    let opened = false;
    field.showPicker = () => { opened = true; };
    field.listeners.get("click")();
    assert.equal(opened, true);
    field.showPicker = () => { throw new Error("Restricted iframe"); };
    assert.doesNotThrow(() => field.listeners.get("click")());
    delete field.showPicker;
    assert.doesNotThrow(() => field.listeners.get("click")());
  }
  fixture.elements.get("schedule-kind").value = "weekly";
  fixture.elements.get("schedule-kind").listeners.get("change")();
  assert.equal(fixture.elements.get("schedule-weekdays").classList.contains("hidden"), false);
  assert.equal(fixture.elements.get("schedule-date").required, false);
  await fixture.elements.get("pause-schedules").listeners.get("click")();
  assert.equal(rows.schedules[0].status, "paused");
}

async function testExplicitFinishedSharing() {
  for (const smtpSent of [false, true]) {
    const link = "https://qurl.invalid/#retained-invitation";
    const grant = {id: "grant_aaaaaaaaaaaaaaaa", label: "Guest", qurl_link: link,
      access_url: link, expires_at: "2099-01-01T00:00:00Z", verification_required: true};
    const persisted = {id: "fixture", title: "Fixture", access_grants: smtpSent ? [{
      id: "existing", label: "Existing guest", expires_at: "2099-01-01T00:00:00Z",
    }] : []};
    const requests = [];
    let failRemoval = false;
    const fixture = harness("admin", {async fetch(route, options = {}) {
      if (route.endsWith("/schedules")) return jsonResponse(200, {schedules: [], occurrences: [], smtp_configured: true, supported: true, timezone: "UTC"});
      requests.push([route, options.method || "GET"]);
      if (route.endsWith("/qurls")) {
        persisted.access_grants.unshift(structuredClone(grant));
        return jsonResponse(201, {grant: structuredClone(grant), email_delivery: {sent: smtpSent}});
      }
      if (route.endsWith("/finish-sharing")) {
        assert.equal(options.method, "POST");
        assert.equal(options.body, "{}");
        if (failRemoval) return jsonResponse(500, {error: "Could not save"});
        persisted.access_grants[0].qurl_link = "";
        delete persisted.access_grants[0].access_url;
      }
      return jsonResponse(200, structuredClone(persisted));
    }});
    fixture.document.createElementNS = () => new Element();
    fixture.context.window.requestAnimationFrame = callback => callback();
    vm.runInContext(fs.readFileSync(path.join(root, "static/vendor/qrcodegen.js"), "utf8"), fixture.context);
    vm.runInContext("window.qrcodegen = qrcodegen", fixture.context);
    fixture.context.copies = [];
    vm.runInContext(`
      currentPage = {id: 'fixture', title: 'Fixture', access_grants: []};
      editingExisting = true; layerVApiConfigured = true;
      selectedLifetime = () => '1h';
      loadPages = async () => {}; loadGuestActivitySummaries = async () => {};
      legacyCopyText = value => { copies.push(value); return true; };
      openUserDialog();
    `, fixture.context);
    await vm.runInContext("manageUsers('fixture')", fixture.context);
    assert.equal(fixture.elements.get("status").textContent,
      smtpSent ? '1 guest configured for “Fixture”.' : '0 guests configured for “Fixture”.');
    fixture.elements.get("qurl-label").value = "Guest";
    fixture.elements.get("send-invitation").checked = true;
    fixture.elements.get("verification-email").value = "guest@example.test";
    await vm.runInContext("generateQurl()", fixture.context);
    assert.equal(fixture.elements.get("status").textContent,
      smtpSent ? '2 guests configured for “Fixture”.' : '1 guest configured for “Fixture”.');
    const result = fixture.elements.get("qurl-result");
    const findResult = text => descendants(result).find(element => element.textContent === text);
    assert.ok(descendants(result).some(element => element.value === link));
    assert.ok(findResult("Finished Sharing"));
    assert.equal(persisted.access_grants[0].qurl_link, link, "SMTP must not finalize sharing");
    findResult("Copy guest link").listeners.get("click")();
    await settle();
    assert.equal(fixture.context.copies[0], link);
    assert.ok(descendants(result).some(element => element.attributes.get("viewBox")), "Real local QR rendered");
    findResult("Show QR codes").listeners.get("click")();
    assert.ok(decodeURIComponent(findResult("Compose email").href).includes(link));
    findResult("Compose email").listeners.get("click")({preventDefault() { throw new Error("Unexpected block"); }});
    const messages = findResult("Open Messages + copy");
    assert.match(messages.href, /^sms:/);
    messages.listeners.get("click")();
    assert.ok(fixture.context.copies.some(value => value.includes(link)));
    const shares = [];
    fixture.context.navigator.share = async data => shares.push(data);
    const native = vm.runInContext("buildSharePanel('Guest', currentPage.access_grants[0].qurl_link)", fixture.context);
    await descendants(native).find(element => element.textContent === "Share…").listeners.get("click")();
    assert.ok(shares[0].text.includes(link));
    assert.equal(requests.length, 2, "Copy/share/QR/email must not finalize");

    const cancelled = findResult("Finished Sharing").listeners.get("click")();
    assert.equal(fixture.elements.get("confirm-title").textContent, "Finished sharing this invitation?");
    assert.equal(fixture.elements.get("accept-confirm").textContent, "Remove Saved Link");
    assert.match(fixture.elements.get("confirm-message").textContent, /invitation will continue to work normally/);
    fixture.elements.get("cancel-confirm").listeners.get("click")();
    await cancelled;
    fixture.elements.get("close-user-dialog").listeners.get("click")();
    await vm.runInContext("manageUsers('fixture')", fixture.context);
    let buttons = descendants(fixture.elements.get("grant-list"));
    assert.ok(buttons.some(element => element.textContent === "Copy guest link"));
    assert.ok(buttons.some(element => element.textContent === "Finished Sharing"));
    assert.equal(persisted.access_grants[0].qurl_link, link);
    assert.equal(requests.filter(([route]) => route.endsWith("/finish-sharing")).length, 0);

    failRemoval = true;
    const failed = buttons.find(element => element.textContent === "Finished Sharing").listeners.get("click")();
    fixture.elements.get("accept-confirm").listeners.get("click")();
    await failed;
    assert.equal(persisted.access_grants[0].qurl_link, link);
    assert.match(fixture.elements.get("status").textContent, /Could not save/);
    failRemoval = false;
    // Finalize an existing guest after reopening, also clearing its hidden result.
    const finished = buttons.find(element => element.textContent === "Finished Sharing").listeners.get("click")();
    fixture.elements.get("accept-confirm").listeners.get("click")();
    await finished;
    assert.equal(persisted.access_grants[0].qurl_link, "");
    assert.equal(vm.runInContext("currentPage.access_grants[0].qurl_link", fixture.context), "");
    assert.equal(vm.runInContext("'access_url' in currentPage.access_grants[0]", fixture.context), false);
    assert.equal(descendants(result).some(element => element.value === link || element.href?.includes(link)), false);
    await vm.runInContext("manageUsers('fixture')", fixture.context);
    buttons = descendants(fixture.elements.get("grant-list"));
    assert.equal(buttons.some(element => ["Copy guest link", "Finished Sharing"].includes(element.textContent)), false);
    for (const label of ["View activity", "Revoke this link", "Invitation shared — link no longer stored"]) {
      assert.ok(buttons.some(element => element.textContent === label), label);
    }
    const ordinary = vm.runInContext("confirmAction('Ordinary confirmation')", fixture.context);
    assert.equal(fixture.elements.get("accept-confirm").textContent, "Confirm");
    assert.equal(fixture.elements.get("confirm-title").textContent, "Confirm this action");
    fixture.elements.get("close-confirm-dialog").listeners.get("click")();
    assert.equal(await ordinary, false);
    assert.equal(requests.filter(([route]) => route.endsWith("/qurls")).length, 1, "No replacement minted");
    assert.equal(requests.some(([, method]) => method === "DELETE"), false);
  }
}

async function testCompatibilityRepairAndTilt() {
  const fixture = harness("admin", {async fetch() { return jsonResponse(200, {}); }});
  vm.runInContext(`
    discovery = {entities: [{entity_id: "cover.blind", name: "New HA name", domain: "cover",
      state: "open", actions: [{service: "open_cover_tilt", name: "Open tilt"}]}]};
    loadSelections({resources: [
      {entity_id: "cover.blind", name: "Owner label", actions: [{service: "open_cover"}]},
      {entity_id: "switch.missing", name: "Saved missing label", actions: [{service: "turn_on"}]},
    ]});
    renderCatalog();
  `, fixture.context);
  const text = descendants(fixture.elements.get("catalog")).map(item => item.textContent).join(" ");
  assert.match(text, /Saved controls are no longer supported/);
  assert.match(text, /saved entity is missing/);
  assert.match(text, /Saved missing label/);
  assert.throws(() => vm.runInContext("buildPagePayload()", fixture.context), /unsupported controls/);
  assert.equal(vm.runInContext("selections.get('cover.blind').has('open_cover_tilt')", fixture.context), false);
  vm.runInContext("selections.set('cover.blind', new Set(['open_cover_tilt']))", fixture.context);
  assert.throws(() => vm.runInContext("buildPagePayload()", fixture.context), /unavailable or excluded/);
  const remove = descendants(fixture.elements.get("catalog"))
    .find(item => item.textContent === "Remove unavailable resource");
  remove.listeners.get("click")();
  const payload = vm.runInContext("buildPagePayload()", fixture.context);
  assert.equal(payload.resources.length, 1);
  assert.equal(payload.resources[0].name, "Owner label");
  assert.equal(payload.resources[0].entity_id, "cover.blind");
  assert.equal(payload.resources[0].actions[0].service, "open_cover_tilt");

  const guest = harness("access", {});
  for (const state of ["open", "closed", "opening", "closing"]) {
    guest.context.fixtureResource = {domain: "cover", state, capabilities: {cover: {tilt_position: 40}}};
    for (const id of ["open_cover_tilt", "close_cover_tilt", "stop_cover_tilt"]) {
      guest.context.fixtureAction = {id};
      assert.equal(vm.runInContext("actionVisibility(fixtureResource, fixtureAction).disabled", guest.context), false);
    }
  }
}

(async () => {
  await testCompatibilityRepairAndTilt();
  await testVerificationOptionAvailability();
  await testScheduledGuestWorkflow();
  await testGuestDraftAndValidation();
  await testExplicitFinishedSharing();
  await testActionFreshState();
  await testPrecommandReadCannotFinalizeAction();
  await testObsoleteResponses();
  await testInterruptedActionsAndCamera();
  await testInvitationAndRevocationFeedback();
  await assertBodyTimeoutKeepsRequestId();
  await testAdminReset();
  await testGuestVisibility();
  await testRevocationOnReturn();
  await testUnavailableOnReturn();
  await testVerificationPause();
  await testVerificationRecovery();
  console.log("Frontend runtime reset and visibility tests passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
