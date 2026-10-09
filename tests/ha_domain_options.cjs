const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

// Home Assistant's text-selector change handler, with TypeScript annotations
// removed. Capture its event without loading Lit or the full HA frontend.
// https://github.com/home-assistant/frontend/blob/dev/src/components/ha-selector/ha-selector-text.ts
// Supervisor marks a schema ending in "?" optional, then merges saved options
// over App defaults when reading them back:
// https://github.com/home-assistant/supervisor/blob/main/supervisor/apps/options.py
// https://github.com/home-assistant/supervisor/blob/main/supervisor/apps/app.py
function fireEvent(target, _name, detail) {
  target.change = detail;
}

function handleChange(ev) {
  ev.stopPropagation();
  let value = ev.detail?.value ?? ev.target.value;
  if (this.value === value) {
    return;
  }
  if (
    (value === "" || (Array.isArray(value) && value.length === 0)) &&
    !this.required
  ) {
    value = undefined;
  }
  fireEvent(this, "value-changed", { value });
}

const config = fs.readFileSync(
  path.join(__dirname, "../homeassistant-app/config.yaml"), "utf8"
);
function domainSetting(section) {
  const body = config.split(`${section}:\n`)[1].split(/^\S/m)[0];
  return body.match(/^  include_domains: "([^"]*)"$/m)[1];
}
const defaults = { include_domains: domainSetting("options") };
function saveClearedField(schema, previous) {
  const selector = { value: previous, required: !schema.endsWith("?") };
  handleChange.call(selector, {
    stopPropagation() {}, target: { value: "" },
  });
  // Undefined properties disappear from the frontend's JSON API request.
  const saved = JSON.parse(JSON.stringify({ include_domains: selector.change.value }));
  return { ...defaults, ...saved };
}

// Reproduce the old schema restoring defaults after the field is cleared.
assert.deepEqual(saveClearedField("str?", defaults.include_domains), defaults);
const reloaded = saveClearedField(domainSetting("schema"), defaults.include_domains);
assert.equal(reloaded.include_domains, "");
assert.deepEqual(JSON.parse(JSON.stringify(reloaded)), { include_domains: "" });
process.stdout.write(JSON.stringify(reloaded));
