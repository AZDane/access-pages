import {createAdminApi} from "./admin-api.js";

const params = new URLSearchParams(window.location.search);
const tokenFromUrl = params.get("token");
const storedToken = sessionStorage.getItem("adminToken");

if (tokenFromUrl) {
  sessionStorage.setItem("adminToken", tokenFromUrl);
}

const adminToken = tokenFromUrl || storedToken || "";
const adminApi = createAdminApi(adminToken);

if (tokenFromUrl) {
  history.replaceState(null, "", window.location.pathname);
}

const statusBox = document.getElementById("status");
const dashboard = document.getElementById("dashboard");
const editor = document.getElementById("editor");
const users = document.getElementById("users");
const pageList = document.getElementById("page-list");
const newPageButton = document.getElementById("new-page");
const backButton = document.getElementById("back");
const saveButton = document.getElementById("save");
const deleteButton = document.getElementById("delete");
const previewLink = document.getElementById("preview");
const editorUsersButton = document.getElementById("editor-users");
const editorUsersBottomButton =
  document.getElementById("editor-users-bottom");
const saveBottomButton = document.getElementById("save-bottom");
const refreshButton = document.getElementById("refresh");

const titleInput = document.getElementById("title");
const pageIdInput = document.getElementById("page-id");
const descriptionInput = document.getElementById("description");
const proximityEnabledInput = document.getElementById("proximity-enabled");
const proximityRadiusInput = document.getElementById("proximity-radius");
const proximityRadiusField = document.getElementById("proximity-radius-field");
const selectedCount = document.getElementById("selected-count");
const openPickerButton = document.getElementById("open-picker");
const pickerDialog = document.getElementById("entity-picker");
const closePickerButton = document.getElementById("close-picker");
const pickerDoneButton = document.getElementById("picker-done");
const pickerSearchInput = document.getElementById("picker-search");
const pickerTypes = document.getElementById("picker-types");
const pickerResults = document.getElementById("picker-results");
const pickerPolicy = document.getElementById("picker-policy");
const pickerTargetTab = document.getElementById("picker-target-tab");
const pickerTypeTab = document.getElementById("picker-type-tab");
const usersBackButton = document.getElementById("users-back");
const usersEditButton = document.getElementById("users-edit");
const usersPreviewButton = document.getElementById("users-preview");
const usersTitle = document.getElementById("users-title");
const addUserButton = document.getElementById("add-user");
const userDialog = document.getElementById("user-dialog");
const userDialogStatus = document.getElementById("user-dialog-status");
const closeUserDialogButton = document.getElementById("close-user-dialog");
const qurlLabelInput = document.getElementById("qurl-label");
const oneTimeUseInput = document.getElementById("one-time-use");
const verificationRequiredInput = document.getElementById("verification-required");
const activityNotificationsInput = document.getElementById("activity-notifications");
const activityNotificationOptions = document.getElementById("activity-notification-options");
const notificationTargets = document.getElementById("notification-targets");
const configureNotificationsButton = document.getElementById("configure-notifications");
const verificationEmailField = document.getElementById("verification-email-field");
const verificationEmailInput = document.getElementById("verification-email");
const sendInvitationInput = document.getElementById("send-invitation");

function configureInvitationEmail() {
  sendInvitationInput.disabled = !emailConfigured;
  if (!emailConfigured) sendInvitationInput.checked = false;
  if (!emailConfigured || !scopedGuestSupported) verificationRequiredInput.checked = false;
  verificationEmailField.classList.toggle(
    "hidden", !sendInvitationInput.checked && !verificationRequiredInput.checked,
  );
  document.getElementById("verification-option").classList.toggle("hidden", !emailConfigured);
  verificationRequiredInput.disabled = !emailConfigured || !scopedGuestSupported;
  document.getElementById("invitation-email-help").textContent = !emailConfigured
    ? "Configure SMTP to send guest invitations."
    : "Send the guest a link by email.";
}
const verificationHelp = document.getElementById("verification-help");
const customLifetime = document.getElementById("custom-lifetime");
const customLifetimeValue = document.getElementById(
  "custom-lifetime-value",
);
const customLifetimeUnit = document.getElementById(
  "custom-lifetime-unit",
);
const lifetimeLimit = document.getElementById("lifetime-limit");
const generateQurlButton = document.getElementById("generate-qurl");
const revokeQurlsButton = document.getElementById("revoke-qurls");
const qurlResult = document.getElementById("qurl-result");
const grantList = document.getElementById("grant-list");
const grantCount = document.getElementById("grant-count");
const revokedList = document.getElementById("revoked-list");
const revokedCount = document.getElementById("revoked-count");
const securityEventList = document.getElementById("security-event-list");
const securityEventCount = document.getElementById("security-event-count");
const activityDialog = document.getElementById("activity-dialog");
const closeActivityDialogButton =
  document.getElementById("close-activity-dialog");
const activityTitle = document.getElementById("activity-title");
const activitySummary = document.getElementById("activity-summary");
const activityList = document.getElementById("activity-list");
const deleteActivityButton = document.getElementById("delete-activity");
const catalog = document.getElementById("catalog");
const openResetDialogButton = document.getElementById("open-reset-dialog");
const resetDialog = document.getElementById("reset-dialog");
const closeResetDialogButton = document.getElementById("close-reset-dialog");
const cancelResetButton = document.getElementById("cancel-reset");
const confirmResetButton = document.getElementById("confirm-reset");
const resetConfirmationInput =
  document.getElementById("reset-confirmation");
const resetStatus = document.getElementById("reset-status");
const gatewayVersion = document.getElementById("gateway-version");
const gatewayHealth = document.getElementById("gateway-health");
const gatewayLayerV = document.getElementById("gateway-layerv");
const gatewayPages = document.getElementById("gateway-pages");
const gatewayConnectors = document.getElementById("gateway-connectors");
const gatewayGuests = document.getElementById("gateway-guests");
const gatewayEmail = document.getElementById("gateway-email");
const gatewayNotifications = document.getElementById("gateway-notifications");
const configureEmailButton = document.getElementById("configure-email");
const emailDialog = document.getElementById("email-dialog");
const closeEmailDialogButton = document.getElementById("close-email-dialog");
const emailForm = document.getElementById("email-form");
const saveEmailButton = document.getElementById("save-email");
const smtpHost = document.getElementById("smtp-host");
const smtpPort = document.getElementById("smtp-port");
const smtpSecurity = document.getElementById("smtp-security");
const smtpUsername = document.getElementById("smtp-username");
const smtpPassword = document.getElementById("smtp-password");
const smtpSenderEmail = document.getElementById("smtp-sender-email");
const smtpSenderName = document.getElementById("smtp-sender-name");
const smtpAdministratorEmail = document.getElementById("smtp-administrator-email");
const alertMobileTargets = document.getElementById("alert-mobile-targets");
const smtpTestRecipient = document.getElementById("smtp-test-recipient");
const testEmailButton = document.getElementById("test-email");
const emailStatus = document.getElementById("email-status");
let availableMobileAlertTargets = [];
let savedMobileAlertTargets = new Set();
const confirmDialog = document.getElementById("confirm-dialog");
const confirmTitle = document.getElementById("confirm-title");
const confirmMessage = document.getElementById("confirm-message");
const closeConfirmDialogButton = document.getElementById(
  "close-confirm-dialog",
);
const cancelConfirmButton = document.getElementById("cancel-confirm");
const acceptConfirmButton = document.getElementById("accept-confirm");

let pages = [];
let discovery = {entities: []};
let currentPage = null;
let editingExisting = false;
let layerVApiConfigured = false;
let emailConfigured = false;
let scopedGuestSupported = false;

function configureGuestOptions() {
  configureInvitationEmail();
  oneTimeUseInput.disabled = !scopedGuestSupported;
  document.getElementById("one-time-help").textContent = scopedGuestSupported
    ? "LayerV admits this qURL once. Single-use guest access lasts at most 24 hours."
    : "Native single-use invitations require the current LayerV Connector runtime.";
  verificationHelp.textContent = !scopedGuestSupported
    ? "Guest-specific verification requires the current Gateway invitation flow."
    : emailConfigured
      ? "Verify the guest's email at the Gateway after LayerV admission, before showing controls."
      : "Configure email delivery in Gateway health before enabling verification.";
}
let registeredNotificationOptions = [];
let qurlMaxLifetimeDays = 30;
let idWasManuallyEdited = false;
let applicationReady = false;
let activityGuests = [];
let pageSecurityEvents = [];
let selectedActivityGuest = null;
const selections = new Map();
const customNames = new Map();
const cameraRefreshIntervals = new Map();
let selectionOrder = [];
let pickerBrowseMode = "type";
let activePickerCategory = null;
let confirmationResolver = null;

function settleConfirmation(accepted) {
  if (!confirmationResolver) return;
  const resolve = confirmationResolver;
  confirmationResolver = null;
  confirmDialog.close();
  resolve(accepted);
}

function confirmAction(message, {title = "Confirm this action", acceptLabel = "Confirm", safeDefault = false} = {}) {
  if (confirmationResolver) {
    return Promise.resolve(false);
  }
  return new Promise((resolve) => {
    confirmationResolver = resolve;
    confirmTitle.textContent = title;
    confirmMessage.textContent = message;
    acceptConfirmButton.textContent = acceptLabel;
    confirmDialog.showModal();
    (safeDefault ? cancelConfirmButton : acceptConfirmButton).focus();
  });
}

closeConfirmDialogButton.addEventListener("click", () => {
  settleConfirmation(false);
});
cancelConfirmButton.addEventListener("click", () => {
  settleConfirmation(false);
});
acceptConfirmButton.addEventListener("click", () => {
  settleConfirmation(true);
});
confirmDialog.addEventListener("cancel", (event) => {
  event.preventDefault();
  settleConfirmation(false);
});
confirmDialog.addEventListener("click", (event) => {
  if (event.target === confirmDialog) {
    settleConfirmation(false);
  }
});

configureEmailButton.addEventListener("click", () => {
  openEmailSettings().catch((error) => setStatus(`Error: ${error.message}`, "error"));
});
closeEmailDialogButton.addEventListener("click", () => emailDialog.close());
emailForm.addEventListener("submit", saveEmailSettings);
testEmailButton.addEventListener("click", sendTestEmail);
verificationRequiredInput.addEventListener("change", () => {
  configureInvitationEmail();
  if (verificationRequiredInput.checked) verificationEmailInput.focus();
});
sendInvitationInput.addEventListener("change", configureInvitationEmail);
activityNotificationsInput.addEventListener("change", () => {
  activityNotificationOptions.classList.toggle(
    "hidden", !activityNotificationsInput.checked,
  );
});
configureNotificationsButton.addEventListener("click", async () => {
  if (!await requestGuestClose(userDialog)) return;
  openEmailSettings().catch((error) => setStatus(`Error: ${error.message}`, "error"));
});

function renderNotificationTargets(options) {
  registeredNotificationOptions = options;
  notificationTargets.replaceChildren();
  for (const option of options) {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = "notification-target";
    input.value = option.value;
    const text = document.createElement("span");
    text.textContent = option.label;
    label.append(input, text);
    notificationTargets.appendChild(label);
  }
  if (!options.length) {
    const note = document.createElement("small");
    note.textContent = "No alert destinations are configured. Add an administrator email below, or register a Home Assistant Companion App device.";
    notificationTargets.appendChild(note);
  }
  configureNotificationsButton.classList.toggle("hidden", options.length > 0);
}

async function loadNotificationOptions() {
  const response = await adminApi.fetch("api/admin/notification-options", {cache: "no-store"});
  const data = await responseJson(response, "Could not load notification options");
  if (!response.ok) throw new Error(data.error || "Could not load notification options");
  const options = [];
  if (data.email?.configured) {
    options.push({value: "email", label: `Email · ${data.email.address}`});
  }
  for (const target of data.mobile_targets || []) {
    options.push({value: target, label: target.replace("notify.mobile_app_", "Mobile · ").replaceAll("_", " ")});
  }
  renderNotificationTargets(options);
  gatewayNotifications.textContent = options.length
    ? `${options.length} configured`
    : "Setup required";
}

async function responseJson(response, fallback) {
  const contentType = response.headers.get("content-type") || "";
  const body = await response.text();

  try {
    return JSON.parse(body);
  } catch (error) {
    const detail = contentType
      ? `HTTP ${response.status} returned ${contentType}`
      : `HTTP ${response.status} returned a non-JSON response`;
    throw new Error(`${fallback}: ${detail}`);
  }
}

async function waitForServiceStatus(expectedStatus, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await adminApi.fetch(
        `health?transition=${Date.now()}`,
        {cache: "no-store"},
      );
      const result = await response.json();
      if (response.ok && result.status === expectedStatus) {
        return true;
      }
    } catch (_error) {
      // The upstream is expected to be briefly unavailable while it swaps.
    }
    await new Promise((resolve) => window.setTimeout(resolve, 500));
  }
  return false;
}

function openSetupPage() {
  // Ingress serves a different document in setup mode. A new, uncached
  // /admin request loads that authoritative form into the same Ingress view.
  const setupUrl = new URL("admin", document.baseURI);
  setupUrl.searchParams.set("reset", String(Date.now()));
  window.location.replace(setupUrl.toString());
}

async function resetLayerVConnection() {
  confirmResetButton.disabled = true;
  resetStatus.className = "status";
  resetStatus.textContent =
    "Revoking guests and resetting the LayerV connection…";
  setStatus("Revoking guests and resetting the LayerV connection…");
  try {
    let response;
    try {
      response = await adminApi.fetch("api/admin/connection/reset", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({confirmation: resetConfirmationInput.value}),
      });
    } catch (error) {
      // The supervisor may switch upstreams before Ingress receives the
      // response. Only the new service's health state can confirm success.
      if (await waitForServiceStatus("setup_required")) {
        openSetupPage();
        return;
      }
      throw error;
    }
    if (!response.ok) {
      const data = await responseJson(
        response,
        "Could not reset the LayerV connection",
      );
      throw new Error(data.error || "Could not reset the LayerV connection");
    }
    // The gateway can close while Ingress is forwarding the accepted response.
    // Setup mode is confirmed by /health below, not by this response body.
    let data = {};
    try {
      data = await responseJson(response, "Could not reset the LayerV connection");
    } catch (_error) {
      // The reset was accepted; the supervisor may have replaced the gateway.
    }
    resetDialog.close();
    const cleanupNote = (data.remote_failures || []).length
      ? ` ${data.remote_failures.length} remote qURL cleanup attempt(s) failed; local access is still revoked.`
      : "";
    setStatus(
      `Reset accepted. Reconnecting…${cleanupNote}`,
      "success",
    );
    if (await waitForServiceStatus("setup_required")) {
      openSetupPage();
    } else {
      setStatus(
        "The reset completed, but onboarding is taking longer than expected. " +
        "Reopen Access Pages from the sidebar.",
        "error",
      );
    }
  } catch (error) {
    resetStatus.className = "status error";
    resetStatus.textContent = `Error: ${error.message}`;
    setStatus(`Error: ${error.message}`, "error");
    confirmResetButton.disabled =
      resetConfirmationInput.value !== "RESET";
  }
}

async function openAdminPreview(pageId) {
  const response = await adminApi.fetch(
    `api/admin/pages/${encodeURIComponent(pageId)}/preview`,
    {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: "{}",
    },
  );
  const data = await responseJson(response, "Could not create preview");

  if (!response.ok) {
    throw new Error(data.error || "Could not create preview");
  }

  // Home Assistant's mobile app may open a new window in a separate WebView
  // that does not inherit the authenticated Ingress session. Staying in the
  // current view preserves that session; the Back action returns to admin.
  window.location.assign(data.preview_url);
}

function setStatus(message, kind = "") {
  statusBox.className = `status ${kind}`.trim();
  statusBox.textContent = message;
}

async function loadGatewayStatus() {
  try {
    const response = await adminApi.fetch("health", {cache: "no-store"});
    const data = await responseJson(
      response,
      "Could not load Gateway status",
    );
    if (!response.ok) {
      throw new Error(data.error || "Gateway health check failed");
    }

    gatewayVersion.textContent = data.version || "Unknown";
    gatewayHealth.textContent =
      data.status === "ok" ? "Online" : "Unavailable";
    gatewayLayerV.textContent = data.layerv_recovery_required
      ? "Recovery required — reset LayerV connection"
      : data.layerv_api_configured ? "Configured" : "Setup required";
    gatewayEmail.textContent = data.email_configured
      ? "Configured"
      : "Not configured";
    emailConfigured = Boolean(data.email_configured);
    scopedGuestSupported = Boolean(data.guest_features?.scoped_invitations);
    try {
      await loadNotificationOptions();
    } catch (_error) {
      renderNotificationTargets([]);
      gatewayNotifications.textContent = "Unavailable";
    }
    configureGuestOptions();
    gatewayPages.textContent = String(data.page_count ?? pages.length);
    const connectorTotal = Number(data.connectors?.total ?? 0);
    const connectorActive = Number(data.connectors?.active ?? 0);
    const connectorDormant = Math.max(0, connectorTotal - connectorActive);
    if (data.connectors?.mode === "shared") {
      const endpoints = Number(data.connectors.page_endpoints ?? 0);
      gatewayConnectors.textContent = `Shared Connector · ${endpoints} page endpoints`;
    } else {
      gatewayConnectors.textContent =
        `${connectorActive} active · ${connectorDormant} dormant · ${connectorTotal} total`;
    }
  } catch (_error) {
    gatewayVersion.textContent = "Unknown";
    gatewayHealth.textContent = "Unavailable";
    gatewayLayerV.textContent = "Unknown";
    gatewayEmail.textContent = "Unknown";
    gatewayNotifications.textContent = "Unknown";
    gatewayPages.textContent = String(pages.length);
    gatewayConnectors.textContent = "Unknown";
  }

  updateGatewayCounts();
}

function setEmailStatus(message, kind = "") {
  emailStatus.className = `status ${kind}`.trim();
  emailStatus.textContent = message;
}

async function testMobileAlertTarget(target, button) {
  button.disabled = true;
  const originalText = button.textContent;
  button.textContent = "Sending…";
  try {
    const response = await adminApi.fetch("api/admin/alerts/test", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target}),
    });
    const data = await responseJson(response, "Could not send mobile test");
    if (!response.ok) throw new Error(data.error || "Could not send mobile test");
    button.textContent = "Sent ✓";
    setEmailStatus(`Test notification sent to ${target}.`, "success");
    setTimeout(() => { button.textContent = originalText; }, 1800);
  } catch (error) {
    button.textContent = originalText;
    setEmailStatus(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function renderMobileAlertTargets() {
  alertMobileTargets.replaceChildren();
  for (const target of availableMobileAlertTargets) {
    const row = document.createElement("div");
    row.className = "mobile-alert-row";
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = "configured-mobile-alert-target";
    input.value = target;
    input.checked = savedMobileAlertTargets.has(target);
    const text = document.createElement("span");
    text.textContent = target.replace("notify.mobile_app_", "Mobile · ").replaceAll("_", " ");
    label.append(input, text);
    const testButton = document.createElement("button");
    testButton.type = "button";
    testButton.className = "secondary";
    testButton.textContent = "Send test";
    testButton.disabled = !savedMobileAlertTargets.has(target);
    testButton.title = testButton.disabled ? "Save this recipient before testing" : "";
    testButton.addEventListener("click", () => testMobileAlertTarget(target, testButton));
    row.append(label, testButton);
    alertMobileTargets.appendChild(row);
  }
  if (!availableMobileAlertTargets.length) {
    const note = document.createElement("small");
    note.textContent = "No notify.mobile_app_* targets were discovered in Home Assistant.";
    alertMobileTargets.appendChild(note);
  }
}

async function openEmailSettings() {
  setEmailStatus("Loading email settings…");
  emailDialog.showModal();
  const response = await adminApi.fetch("api/admin/email/config", {
    cache: "no-store",
  });
  const data = await responseJson(response, "Could not load email settings");
  if (!response.ok) {
    setEmailStatus(data.error || "Could not load email settings", "error");
    return;
  }
  smtpHost.value = data.host || "";
  smtpPort.value = String(data.port || 587);
  smtpSecurity.value = data.security || "starttls";
  smtpUsername.value = data.username || "";
  smtpPassword.value = "";
  smtpSenderEmail.value = data.sender_email || "";
  smtpSenderName.value = data.sender_name || "Access Pages";
  smtpAdministratorEmail.value = data.administrator_email || data.sender_email || "";
  const notificationResponse = await adminApi.fetch("api/admin/notification-options", {
    cache: "no-store",
  });
  const notificationData = await responseJson(
    notificationResponse,
    "Could not load mobile alert destinations",
  );
  if (!notificationResponse.ok) {
    setEmailStatus(notificationData.error || "Could not load mobile alert destinations", "error");
    return;
  }
  availableMobileAlertTargets = notificationData.available_mobile_targets || [];
  savedMobileAlertTargets = new Set(notificationData.mobile_targets || []);
  renderMobileAlertTargets();
  setEmailStatus(data.configured
    ? "Email delivery is configured. A blank password keeps the saved password."
    : "Enter the SMTP submission settings supplied by your email provider.");
}

async function saveEmailSettings(event) {
  event.preventDefault();
  setEmailStatus("Saving email settings…");
  saveEmailButton.disabled = true;
  saveEmailButton.textContent = "Saving…";
  const response = await adminApi.fetch("api/admin/email/config", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      host: smtpHost.value,
      port: Number(smtpPort.value),
      security: smtpSecurity.value,
      username: smtpUsername.value,
      password: smtpPassword.value,
      sender_email: smtpSenderEmail.value,
      sender_name: smtpSenderName.value,
      administrator_email: smtpAdministratorEmail.value,
    }),
  });
  const data = await responseJson(response, "Could not save email settings");
  if (!response.ok) {
    setEmailStatus(data.error || "Could not save email settings", "error");
    saveEmailButton.disabled = false;
    saveEmailButton.textContent = "Save settings";
    return;
  }
  const alertsResponse = await adminApi.fetch("api/admin/alerts/config", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      mobile_targets: [...document.querySelectorAll(
        'input[name="configured-mobile-alert-target"]:checked',
      )].map((input) => input.value),
    }),
  });
  const alertsData = await responseJson(alertsResponse, "Could not save alert destinations");
  if (!alertsResponse.ok) {
    setEmailStatus(alertsData.error || "Could not save alert destinations", "error");
    saveEmailButton.disabled = false;
    saveEmailButton.textContent = "Save settings";
    return;
  }
  savedMobileAlertTargets = new Set(alertsData.mobile_targets || []);
  renderMobileAlertTargets();
  smtpPassword.value = "";
  gatewayEmail.textContent = "Configured";
  emailConfigured = true;
  configureGuestOptions();
  setEmailStatus("Email settings saved securely.", "success");
  saveEmailButton.textContent = "Saved ✓";
  setTimeout(() => {
    saveEmailButton.disabled = false;
    saveEmailButton.textContent = "Save settings";
  }, 1800);
  await loadNotificationOptions();
}

async function sendTestEmail() {
  setEmailStatus("Sending test email…");
  testEmailButton.disabled = true;
  try {
    const response = await adminApi.fetch("api/admin/email/test", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({recipient: smtpTestRecipient.value}),
    });
    const data = await responseJson(response, "Could not send test email");
    if (!response.ok) throw new Error(data.error || "Could not send test email");
    setEmailStatus("Test email sent.", "success");
  } catch (error) {
    setEmailStatus(error.message, "error");
  } finally {
    testEmailButton.disabled = false;
  }
}

function updateGatewayCounts() {
  const guestCount = pages.reduce(
    (total, page) => total + Number(page.grant_count || 0),
    0,
  );
  gatewayPages.textContent = String(pages.length);
  gatewayGuests.textContent = String(guestCount);
}

function slugify(value) {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

function humanize(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function resourceId(entityId) {
  return entityId
    .toLowerCase()
    .replace(".", "_")
    .replace(/[^a-z0-9_-]/g, "_")
    .slice(0, 64);
}

function showDashboard() {
  editor.classList.add("hidden");
  users.classList.add("hidden");
  dashboard.classList.remove("hidden");
  newPageButton.classList.remove("hidden");
  currentPage = null;
  history.replaceState(null, "", "/admin");
}

function showEditor() {
  dashboard.classList.add("hidden");
  users.classList.add("hidden");
  editor.classList.remove("hidden");
  newPageButton.classList.add("hidden");
}

function showUsers() {
  dashboard.classList.add("hidden");
  editor.classList.add("hidden");
  users.classList.remove("hidden");
  newPageButton.classList.add("hidden");
}

function renderPageList() {
  pageList.replaceChildren();

  if (!pages.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.innerHTML = `
      <h2>No access pages yet</h2>
      <p>Create a page, choose its controls, then point a qURL at it.</p>
    `;

    const button = document.createElement("button");
    button.type = "button";
    button.className = "primary";
    button.textContent = "+ Create first page";
    button.disabled = !applicationReady;
    button.addEventListener("click", createNewPage);
    empty.appendChild(button);
    pageList.appendChild(empty);
    return;
  }

  pages.forEach((page) => {
    const card = document.createElement("article");
    card.className = "page-card";

    const copy = document.createElement("div");
    copy.className = "page-copy";

    const name = document.createElement("h2");
    name.textContent = page.title;

    const description = document.createElement("p");
    description.textContent =
      page.description || "No guest description.";

    const metadata = document.createElement("div");
    metadata.className = "page-meta";

    const path = document.createElement("code");
    path.textContent = page.access_path;

    const count = document.createElement("span");
    count.textContent =
      `${page.resource_count} ${page.resource_count === 1 ? "resource" : "resources"}`;

    const userCount = document.createElement("span");
    userCount.textContent =
      `${page.grant_count || 0} ${(page.grant_count || 0) === 1 ? "guest" : "guests"}`;

    metadata.append(path, count, userCount);
    copy.append(name, description, metadata);

    const actions = document.createElement("div");
    actions.className = "page-card-actions";

    const open = document.createElement("button");
    open.type = "button";
    open.className = "primary";
    open.textContent = "Edit";
    open.addEventListener("click", () => editPage(page.id));

    const preview = document.createElement("button");
    preview.type = "button";
    preview.className = "secondary link-button";
    preview.textContent = "Preview";
    preview.addEventListener("click", () => {
      openAdminPreview(page.id).catch((error) => {
        setStatus(`Error: ${error.message}`, "error");
      });
    });

    const manageUsersButton = document.createElement("button");
    manageUsersButton.type = "button";
    manageUsersButton.className = "secondary";
    manageUsersButton.textContent = "Guests";
    manageUsersButton.addEventListener("click", () => manageUsers(page.id));

    actions.append(open, preview, manageUsersButton);
    card.append(copy, actions);
    pageList.appendChild(card);
  });
}

function formatType(value) {
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function loadSelections(page) {
  selections.clear();
  customNames.clear();
  cameraRefreshIntervals.clear();
  selectionOrder = [];

  page.resources.forEach((resource) => {
    selections.set(
      resource.entity_id,
      new Set(resource.actions.map((action) => action.service)),
    );
    customNames.set(resource.entity_id, resource.name);
    if (resource.domain === "camera") {
      cameraRefreshIntervals.set(
        resource.entity_id,
        resource.camera_refresh_interval ?? 30,
      );
    }
    selectionOrder.push(resource.entity_id);
  });
}

function selectedResourceCount() {
  return [...selections.values()]
    .filter((actions) => actions.size > 0)
    .length;
}

function updateSelectionSummary() {
  selectedCount.textContent = selectedResourceCount();
}

function updateSelection(entityId, service, checked, defaultName = "") {
  const wasSelected = selections.has(entityId);
  if (!selections.has(entityId)) {
    selections.set(entityId, new Set());
  }

  const actions = selections.get(entityId);

  if (checked) {
    actions.add(service);
    if (!wasSelected) {
      selectionOrder.push(entityId);
    }
    if (!customNames.has(entityId)) {
      customNames.set(entityId, defaultName || entityId);
    }
  } else {
    actions.delete(service);
  }

  if (!actions.size) {
    selections.delete(entityId);
    customNames.delete(entityId);
    cameraRefreshIntervals.delete(entityId);
    selectionOrder = selectionOrder.filter((item) => item !== entityId);
  }

  updateSelectionSummary();
  renderCatalog();
  renderPicker();
}

function moveSelection(entityId, targetIndex) {
  const currentIndex = selectionOrder.indexOf(entityId);
  if (currentIndex < 0) return;

  const boundedIndex = Math.max(
    0,
    Math.min(targetIndex, selectionOrder.length - 1),
  );
  if (currentIndex === boundedIndex) return;

  selectionOrder.splice(currentIndex, 1);
  selectionOrder.splice(boundedIndex, 0, entityId);
  renderCatalog();
}

function renderCatalog() {
  const entityMap = new Map(
    discovery.entities.map((entity) => [entity.entity_id, entity]),
  );
  const entities = selectionOrder
    .map((entityId) => entityMap.get(entityId) || {
      entity_id: entityId,
      name: customNames.get(entityId) || entityId,
      domain: entityId.split(".")[0],
      state: "Unavailable or excluded",
      actions: [],
    });
  catalog.replaceChildren();

  if (!entities.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state compact";
    empty.innerHTML = `
      <h2>No resources selected</h2>
      <p>Add only the Home Assistant entities this guest page needs.</p>
    `;
    const addButton = document.createElement("button");
    addButton.type = "button";
    addButton.className = "primary";
    addButton.textContent = "+ Add resources";
    addButton.addEventListener("click", openPicker);
    empty.appendChild(addButton);
    catalog.appendChild(empty);
    return;
  }

  const grid = document.createElement("div");
  grid.className = "entity-grid";
  entities.forEach((entity, index) => {
      const card = document.createElement("article");
      card.className = "entity-card selected";
      card.dataset.entityId = entity.entity_id;

      const orderControls = document.createElement("div");
      orderControls.className = "entity-order-controls";

      const dragHandle = document.createElement("button");
      dragHandle.type = "button";
      dragHandle.className = "drag-handle";
      dragHandle.draggable = true;
      dragHandle.textContent = "⋮⋮";
      dragHandle.title = "Drag to reorder";
      dragHandle.setAttribute("aria-label", `Drag ${entity.name} to reorder`);
      dragHandle.addEventListener("dragstart", (event) => {
        event.dataTransfer.effectAllowed = "move";
        event.dataTransfer.setData("text/plain", entity.entity_id);
        card.classList.add("dragging");
      });
      dragHandle.addEventListener("dragend", () => {
        card.classList.remove("dragging");
        document.querySelectorAll(".entity-card.drag-over")
          .forEach((item) => item.classList.remove("drag-over"));
      });

      const up = document.createElement("button");
      up.type = "button";
      up.className = "secondary order-button";
      up.textContent = "↑";
      up.title = "Move up";
      up.setAttribute("aria-label", `Move ${entity.name} up`);
      up.disabled = index === 0;
      up.addEventListener("click", () => moveSelection(entity.entity_id, index - 1));

      const down = document.createElement("button");
      down.type = "button";
      down.className = "secondary order-button";
      down.textContent = "↓";
      down.title = "Move down";
      down.setAttribute("aria-label", `Move ${entity.name} down`);
      down.disabled = index === entities.length - 1;
      down.addEventListener("click", () => moveSelection(entity.entity_id, index + 1));

      orderControls.append(dragHandle, up, down);
      card.appendChild(orderControls);
      card.addEventListener("dragover", (event) => {
        event.preventDefault();
        event.dataTransfer.dropEffect = "move";
        card.classList.add("drag-over");
      });
      card.addEventListener("dragleave", () => card.classList.remove("drag-over"));
      card.addEventListener("drop", (event) => {
        event.preventDefault();
        card.classList.remove("drag-over");
        const draggedId = event.dataTransfer.getData("text/plain");
        if (draggedId && draggedId !== entity.entity_id) {
          moveSelection(draggedId, index);
        }
      });

      const header = document.createElement("div");
      header.className = "entity-heading";

      const identity = document.createElement("div");
      const name = document.createElement("h3");
      name.textContent = entity.name;
      const entityId = document.createElement("code");
      entityId.textContent = entity.entity_id;
      identity.append(name, entityId);

      const state = document.createElement("span");
      state.className = "state";
      state.textContent = entity.state;

      header.append(identity, state);
      card.appendChild(header);

      const type = document.createElement("span");
      type.className = "entity-type";
      type.textContent = formatType(entity.type || entity.domain);
      card.appendChild(type);

      const actionList = document.createElement("div");
      actionList.className = "action-list";

      const availableServices = new Set(entity.actions.map((action) => action.service));
      const unsupported = [...(selections.get(entity.entity_id) || [])]
        .filter((service) => service !== "view" && !availableServices.has(service));
      if (!entityMap.has(entity.entity_id) || unsupported.length) {
        const warning = document.createElement("p");
        warning.className = "status error";
        warning.textContent = !entityMap.has(entity.entity_id)
          ? "This saved entity is missing, unavailable, or excluded. Restore it in Home Assistant, or remove it and deliberately select a replacement."
          : `Saved controls are no longer supported: ${unsupported.join(", ")}. Uncheck them before saving; replacement controls require your selection.`;
        card.appendChild(warning);
      }
      if (!entityMap.has(entity.entity_id)) {
        const remove = document.createElement("button");
        remove.type = "button";
        remove.textContent = "Remove unavailable resource";
        remove.addEventListener("click", () => {
          selections.delete(entity.entity_id);
          customNames.delete(entity.entity_id);
          cameraRefreshIntervals.delete(entity.entity_id);
          selectionOrder = selectionOrder.filter((id) => id !== entity.entity_id);
          updateSelectionSummary();
          renderCatalog();
        });
        card.appendChild(remove);
      }
      const actions = [...entity.actions, ...unsupported.map((service) => ({
        service, name: `${service} (unsupported)`,
      }))];
      if (selections.get(entity.entity_id)?.has("view") && !availableServices.has("view")) {
        actions.push({service: "view", name: "Display"});
      }
      actions.forEach((action) => {
        const label = document.createElement("label");
        label.className = "action-option";

        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked =
          selections.get(entity.entity_id)?.has(action.service) || false;

        checkbox.addEventListener("change", () => {
          updateSelection(
            entity.entity_id,
            action.service,
            checkbox.checked,
            entity.name,
          );
        });

        const actionText = document.createElement("span");
        const actionName = document.createElement("strong");
        actionName.textContent = action.name;
        const serviceName = document.createElement("code");
        serviceName.textContent = action.service === "view"
          ? "Read-only display"
          : `${entity.domain}.${action.service}`;
        actionText.append(actionName, serviceName);

        label.append(checkbox, actionText);
        actionList.appendChild(label);
      });

      card.appendChild(actionList);

      const nameEditor = document.createElement("label");
      nameEditor.className = "custom-name-editor";

        const nameLabel = document.createElement("span");
        nameLabel.textContent = "Guest display name";

        const nameInput = document.createElement("input");
        nameInput.type = "text";
        nameInput.maxLength = 100;
        nameInput.value =
          customNames.get(entity.entity_id) || entity.name;
        nameInput.placeholder = entity.name;

        nameInput.addEventListener("input", () => {
          customNames.set(
            entity.entity_id,
            nameInput.value,
          );
        });

      nameEditor.append(nameLabel, nameInput);
      card.appendChild(nameEditor);

      if (entity.domain === "camera") {
        const refreshEditor = document.createElement("label");
        refreshEditor.className = "custom-name-editor";
        const refreshLabel = document.createElement("span");
        refreshLabel.textContent = "Still-image refresh";
        const refreshSelect = document.createElement("select");
        for (const [value, label] of [
          [15, "15 seconds"], [30, "30 seconds"], [60, "1 minute"],
          [120, "2 minutes"], [300, "5 minutes"], [0, "Manual only"],
        ]) {
          const option = document.createElement("option");
          option.value = String(value);
          option.textContent = label;
          refreshSelect.appendChild(option);
        }
        refreshSelect.value = String(cameraRefreshIntervals.get(entity.entity_id) ?? 30);
        cameraRefreshIntervals.set(entity.entity_id, Number(refreshSelect.value));
        refreshSelect.addEventListener("change", () => {
          cameraRefreshIntervals.set(entity.entity_id, Number(refreshSelect.value));
        });
        refreshEditor.append(refreshLabel, refreshSelect);
        card.appendChild(refreshEditor);
      } else {
        cameraRefreshIntervals.delete(entity.entity_id);
      }

      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "remove-resource";
      remove.textContent = "Remove resource";
      remove.addEventListener("click", () => {
        selections.delete(entity.entity_id);
        customNames.delete(entity.entity_id);
        cameraRefreshIntervals.delete(entity.entity_id);
        selectionOrder = selectionOrder.filter(
          (item) => item !== entity.entity_id,
        );
        updateSelectionSummary();
        renderCatalog();
        renderPicker();
      });
      card.appendChild(remove);

      grid.appendChild(card);
  });
  catalog.appendChild(grid);
}

function pickerEntityMatches(entity, query) {
  if (
    activePickerCategory !== null
    && activePickerCategory !== ""
  ) {
    const category = pickerBrowseMode === "target"
      ? (entity.area_id || "__unassigned")
      : entity.type;
    if (category !== activePickerCategory) {
      return false;
    }
  }
  const haystack = [
    entity.name,
    entity.entity_id,
    entity.state,
    entity.domain,
    entity.type,
  ].join(" ").toLowerCase();
  return !query || haystack.includes(query);
}

function renderPicker() {
  pickerTypes.setAttribute(
    "aria-label",
    pickerBrowseMode === "target"
      ? "Home Assistant areas"
      : "Entity types",
  );
  const categoryCounts = new Map();
  const categoryLabels = new Map();
  discovery.entities.forEach((entity) => {
    const category = pickerBrowseMode === "target"
      ? (entity.area_id || "__unassigned")
      : entity.type;
    const label = pickerBrowseMode === "target"
      ? (entity.area_name || "Not assigned to an area")
      : formatType(entity.type);
    categoryCounts.set(
      category,
      (categoryCounts.get(category) || 0) + 1,
    );
    categoryLabels.set(category, label);
  });

  pickerTypes.replaceChildren();
  const categoryEntries = [
    ["", "All supported", discovery.entities.length],
    ...[...categoryCounts.entries()]
      .map(([category, count]) => [
        category,
        categoryLabels.get(category),
        count,
      ])
      .sort((a, b) => a[1].localeCompare(b[1])),
  ];

  categoryEntries.forEach(([category, label, count]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "picker-type";
    button.classList.toggle(
      "active",
      category === activePickerCategory,
    );
    const typeName = document.createElement("span");
    typeName.textContent = label;
    const typeCount = document.createElement("small");
    typeCount.textContent = count;
    button.append(typeName, typeCount);
    button.addEventListener("click", () => {
      activePickerCategory = category;
      renderPicker();
    });
    pickerTypes.appendChild(button);
  });

  const query = pickerSearchInput.value.trim().toLowerCase();
  if (activePickerCategory === null && !query) {
    pickerResults.replaceChildren();
    const prompt = document.createElement("div");
    prompt.className = "picker-prompt";
    const title = document.createElement("h3");
    title.textContent = pickerBrowseMode === "target"
      ? "Select a Home Assistant area"
      : "Select an entity type";
    const description = document.createElement("p");
    description.textContent =
      `Choose ${pickerBrowseMode === "target" ? "an area" : "a type"} ` +
      "on the left or search across all supported entities.";
    prompt.append(title, description);
    pickerResults.appendChild(prompt);
    return;
  }

  const entities = discovery.entities.filter(
    (entity) => pickerEntityMatches(entity, query),
  );
  pickerResults.replaceChildren();

  const heading = document.createElement("div");
  heading.className = "picker-results-heading";
  const title = document.createElement("h3");
  title.textContent = activePickerCategory
    ? (
      pickerBrowseMode === "target"
        ? categoryLabels.get(activePickerCategory)
        : formatType(activePickerCategory)
    )
    : "All supported entities";
  const count = document.createElement("span");
  count.textContent = `${entities.length} available`;
  heading.append(title, count);
  pickerResults.appendChild(heading);

  if (!entities.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state compact";
    empty.textContent = "No matching entities.";
    pickerResults.appendChild(empty);
    return;
  }

  entities.forEach((entity) => {
    const row = document.createElement("label");
    row.className = "picker-entity";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = selections.has(entity.entity_id);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) {
        if (!selections.has(entity.entity_id)) {
          selectionOrder.push(entity.entity_id);
        }
        selections.set(
          entity.entity_id,
          new Set(entity.actions.map((action) => action.service)),
        );
        customNames.set(entity.entity_id, entity.name);
      } else {
        selections.delete(entity.entity_id);
        customNames.delete(entity.entity_id);
        cameraRefreshIntervals.delete(entity.entity_id);
        selectionOrder = selectionOrder.filter(
          (item) => item !== entity.entity_id,
        );
      }
      updateSelectionSummary();
      renderCatalog();
    });

    const copy = document.createElement("span");
    const name = document.createElement("strong");
    name.textContent = entity.name;
    const details = document.createElement("small");
    details.textContent = [
      entity.entity_id,
      entity.state,
      entity.area_name,
    ].filter(Boolean).join(" · ");
    copy.append(name, details);
    const type = document.createElement("span");
    type.className = "picker-entity-type";
    type.textContent = formatType(entity.type || entity.domain);
    row.append(checkbox, copy, type);
    pickerResults.appendChild(row);
  });
}

function openPicker() {
  pickerSearchInput.value = "";
  activePickerCategory = null;
  const policy = discovery.policy || {};
  if (policy.restricted) {
    const limits = [
      policy.include_areas?.length
        ? `areas: ${policy.include_areas.join(", ")}`
        : "",
      policy.include_device_classes?.length
        ? `types: ${policy.include_device_classes.join(", ")}`
        : "",
      policy.include_domains?.length
        ? `domains: ${policy.include_domains.join(", ")}`
        : "",
      policy.include_entities?.length
        ? `${policy.include_entities.length} explicit entities`
        : "",
    ].filter(Boolean);
    pickerPolicy.textContent =
      `Choices restricted by configuration (${limits.join("; ")}).`;
  } else {
    pickerPolicy.textContent =
      "Showing every entity supported by the gateway.";
  }
  renderPicker();
  pickerDialog.showModal();
  pickerSearchInput.focus();
}

function blankPage() {
  return {
    id: "",
    title: "",
    description: "",
    proximity: {enabled: false, radius_meters: 500},
    resources: [],
    access_grants: [],
  };
}


function selectedLifetime() {
  const selected = document.querySelector(
    'input[name="lifetime"]:checked'
  )?.value || "24h";
  if (selected !== "custom") {
    return selected;
  }

  const amount = Number(customLifetimeValue.value);
  if (!Number.isInteger(amount) || amount < 1) {
    throw guestInputError("Enter a whole-number custom lifetime.", ["custom-lifetime-value"]);
  }

  const secondsPerUnit = {
    m: 60,
    h: 60 * 60,
    d: 24 * 60 * 60,
  };
  const seconds = amount * secondsPerUnit[customLifetimeUnit.value];
  if (seconds > qurlMaxLifetimeDays * 24 * 60 * 60) {
    throw guestInputError(
      `Lifetime exceeds the configured ${qurlMaxLifetimeDays}-day maximum.`, ["custom-lifetime-value", "custom-lifetime-unit"],
    );
  }
  return `${amount}${customLifetimeUnit.value}`;
}

function updateCustomLifetimeLimit() {
  const maximums = {
    m: qurlMaxLifetimeDays * 24 * 60,
    h: qurlMaxLifetimeDays * 24,
    d: qurlMaxLifetimeDays,
  };
  customLifetimeValue.max = String(
    maximums[customLifetimeUnit.value],
  );
}

function configureLifetimeOptions() {
  const maximumSeconds = qurlMaxLifetimeDays * 24 * 60 * 60;
  const choices = document.querySelectorAll(
    'input[name="lifetime"][data-seconds]',
  );
  choices.forEach((choice) => {
    const unavailable = Number(choice.dataset.seconds) > maximumSeconds;
    choice.disabled = unavailable;
    choice.closest("label").title = unavailable
      ? `Exceeds the configured ${qurlMaxLifetimeDays}-day maximum`
      : "";
  });

  const selected = document.querySelector(
    'input[name="lifetime"]:checked',
  );
  if (selected?.disabled) {
    [...choices]
      .filter((choice) => !choice.disabled)
      .at(-1)
      ?.click();
  }

  lifetimeLimit.textContent =
    `Maximum configured lifetime: ${qurlMaxLifetimeDays} ` +
    `${qurlMaxLifetimeDays === 1 ? "day" : "days"}. ` +
    "Set this to match your LayerV plan in App configuration.";
  updateCustomLifetimeLimit();
}

document.querySelectorAll('input[name="lifetime"]').forEach((choice) => {
  choice.addEventListener("change", () => {
    customLifetime.classList.toggle(
      "hidden",
      choice.value !== "custom" || !choice.checked,
    );
    if (choice.value === "custom" && choice.checked) {
      customLifetimeValue.focus();
    }
  });
});

customLifetimeUnit.addEventListener("change", updateCustomLifetimeLimit);

function formatExpiry(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString();
}

function legacyCopyText(value, button) {
  const input = document.createElement("textarea");
  input.value = value;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.left = "-9999px";
  input.style.top = "0";
  const container = button.closest("dialog") || document.body;
  container.appendChild(input);
  input.focus();
  input.select();
  input.setSelectionRange(0, input.value.length);
  try {
    return document.execCommand("copy");
  } finally {
    input.remove();
  }
}

async function copyText(value, button) {
  // Run the synchronous path first while the original click still carries
  // browser user activation. Waiting for a rejected Clipboard API promise can
  // consume that activation before execCommand gets a chance to run.
  let copied = legacyCopyText(value, button);
  if (!copied && navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    copied = true;
  }
  if (!copied) {
    throw new Error(
      "Browser blocked copying; select the displayed link manually.",
    );
  }
  const original = button.textContent;
  button.textContent = "Copied";
  setTimeout(() => {
    button.textContent = original;
  }, 1400);
}

function shareMessage(guestName, activationUrl) {
  return [
    `Access Pages for ${guestName}`,
    "",
    "Open this private LayerV link:",
    activationUrl,
    "",
    "This link grants access. Do not forward it.",
  ].join("\n");
}

function qrCodeSvg(value, label) {
  if (!window.qrcodegen?.QrCode) {
    throw new Error("Local QR encoder did not load.");
  }
  const qr = window.qrcodegen.QrCode.encodeText(
    value,
    window.qrcodegen.QrCode.Ecc.MEDIUM,
  );
  const border = 4;
  const dimension = qr.size + border * 2;
  const namespace = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(namespace, "svg");
  svg.classList.add("share-qr-code");
  svg.setAttribute("viewBox", `0 0 ${dimension} ${dimension}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", label);
  svg.setAttribute("shape-rendering", "crispEdges");

  const background = document.createElementNS(namespace, "rect");
  background.setAttribute("width", "100%");
  background.setAttribute("height", "100%");
  background.setAttribute("fill", "#fff");

  let modules = "";
  for (let y = 0; y < qr.size; y += 1) {
    for (let x = 0; x < qr.size; x += 1) {
      if (qr.getModule(x, y)) {
        modules += `M${x + border},${y + border}h1v1h-1z`;
      }
    }
  }
  const foreground = document.createElementNS(namespace, "path");
  foreground.setAttribute("d", modules);
  foreground.setAttribute("fill", "#000");
  svg.append(background, foreground);
  return svg;
}

function buildSharePanel(guestName, activationUrl) {
  const panel = document.createElement("section");
  panel.className = "link-sharing";

  const heading = document.createElement("h3");
  heading.textContent = "Share an Access Page";
  const explanation = document.createElement("p");
  explanation.className = "share-note";
  explanation.textContent = navigator.share
    ? "Use Share to choose Messages, Mail, AirDrop, or another app. QR codes " +
      "are created on this device; the Gateway does not send recipient data."
    : "QR codes are created on this device. Email opens with the message " +
      "filled in. Text opens Messages and copies the message for you to paste. " +
      "The Gateway does not send or store recipients.";

  const message = shareMessage(guestName, activationUrl);
  const actions = document.createElement("div");
  actions.className = "share-actions";

  if (navigator.share) {
    const nativeShare = document.createElement("button");
    nativeShare.type = "button";
    nativeShare.className = "primary";
    nativeShare.textContent = "Share…";
    nativeShare.addEventListener("click", async () => {
      try {
        await navigator.share({
          title: `Access Pages for ${guestName}`,
          text: message,
        });
      } catch (error) {
        if (error.name !== "AbortError") {
          setStatus(`Share failed: ${error.message}`, "error");
        }
      }
    });
    actions.appendChild(nativeShare);
  }

  const qrToggle = document.createElement("button");
  qrToggle.type = "button";
  qrToggle.className = "secondary";
  qrToggle.textContent = "Show QR codes";

  const qrGrid = document.createElement("div");
  qrGrid.className = "share-qr-grid hidden";
  [["Access Pages qURL", activationUrl]].forEach(([title, value]) => {
    const card = document.createElement("figure");
    card.className = "share-qr-card";
    const caption = document.createElement("figcaption");
    caption.textContent = title;
    card.append(qrCodeSvg(value, `${title} QR code`), caption);
    qrGrid.appendChild(card);
  });
  qrToggle.addEventListener("click", () => {
    const isHidden = qrGrid.classList.toggle("hidden");
    qrToggle.textContent = isHidden ? "Show QR codes" : "Hide QR codes";
  });
  actions.appendChild(qrToggle);

  panel.append(heading, explanation, actions, qrGrid);

  if (!navigator.share) {
    const recipients = document.createElement("div");
    recipients.className = "share-recipients";

    const emailLabel = document.createElement("label");
    emailLabel.textContent = "Email recipient (optional)";
    const emailInput = document.createElement("input");
    emailInput.type = "email";
    emailInput.autocomplete = "email";
    emailInput.placeholder = "guest@example.com";
    const emailLink = document.createElement("a");
    emailLink.className = "link-button secondary";
    emailLink.target = "_top";
    emailLink.textContent = "Compose email";
    const updateEmailHref = () => {
      const recipient = emailInput.value.trim();
      const subject = `Access Pages for ${guestName}`;
      emailLink.href =
        `mailto:${encodeURIComponent(recipient)}?subject=${encodeURIComponent(subject)}` +
        `&body=${encodeURIComponent(message)}`;
    };
    emailInput.addEventListener("input", updateEmailHref);
    updateEmailHref();
    emailLink.addEventListener("click", (event) => {
      if (emailInput.value && !emailInput.checkValidity()) {
        event.preventDefault();
        emailInput.reportValidity();
      }
    });
    emailLabel.appendChild(emailInput);

    const phoneLabel = document.createElement("label");
    phoneLabel.textContent = "Mobile number (optional)";
    const phoneInput = document.createElement("input");
    phoneInput.type = "tel";
    phoneInput.autocomplete = "tel";
    phoneInput.inputMode = "tel";
    phoneInput.placeholder = "+1 555 555 0123";
    const smsLink = document.createElement("a");
    smsLink.className = "link-button secondary";
    smsLink.target = "_top";
    smsLink.textContent = "Open Messages + copy";
    const updateSmsHref = () => {
      const recipient = phoneInput.value.trim().replace(/[^+0-9]/g, "");
      smsLink.href = `sms:${recipient}`;
    };
    phoneInput.addEventListener("input", updateSmsHref);
    updateSmsHref();
    smsLink.addEventListener("click", () => {
      if (!legacyCopyText(message, smsLink)) {
        setStatus(
          "Messages opened, but copying was blocked. Copy the links manually.",
          "error",
        );
      }
    });
    phoneLabel.appendChild(phoneInput);

    recipients.append(emailLabel, emailLink, phoneLabel, smsLink);
    panel.appendChild(recipients);
  }
  return panel;
}

const sharedInvitationStatus = "Invitation shared — link no longer stored";

function finishedSharingButton(pageId, grant) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "secondary";
  button.textContent = "Finished Sharing";
  button.addEventListener("click", () => finishSharing(pageId, grant, button));
  return button;
}

async function finishSharing(pageId, grant, button) {
  if (button.disabled) return;
  const confirmed = await confirmAction(
    "Access Pages will remove its saved copy of this guest link. " +
    "The guest's invitation will continue to work normally, but you won't be able to copy this same link again. " +
    "If you need another invitation later, create a new guest invitation.",
    {title: "Finished sharing this invitation?", acceptLabel: "Remove Saved Link"},
  );
  if (!confirmed) return;
  button.disabled = true;
  try {
    const response = await adminApi.fetch(
      `api/admin/pages/${encodeURIComponent(pageId)}/grants/${encodeURIComponent(grant.id)}/finish-sharing`,
      {method: "POST", headers: {"Content-Type": "application/json"}, body: "{}"},
    );
    const data = await responseJson(response, "Could not remove the saved guest link");
    if (!response.ok) throw new Error(data.error || "Could not remove the saved guest link");

    grant.qurl_link = "";
    delete grant.access_url;
    if (currentPage?.id === pageId) {
      currentPage.access_grants = data.access_grants;
      renderAccessGrants(currentPage);
    }
    if (qurlResult.dataset.pageId === pageId && qurlResult.dataset.grantId === grant.id) {
      const status = document.createElement("p");
      status.textContent = sharedInvitationStatus;
      qurlResult.replaceChildren(status);
    }
    if (userDialog.open) setUserDialogStatus(sharedInvitationStatus, "success");
    else setStatus(sharedInvitationStatus, "success");
  } catch (error) {
    if (userDialog.open) setUserDialogStatus(`Error: ${error.message}`, "error");
    else setStatus(`Error: ${error.message}`, "error");
  } finally {
    button.disabled = false;
  }
}

function renderAccessGrants(page) {
  const scheduled = scheduleData.page_id === page?.id ? scheduleData.scheduled_grants || {} : {};
  const grants = (page?.access_grants || []).filter(grant => !scheduled[grant.id]);
  grantCount.textContent = String(grants.length);
  grantList.replaceChildren();
  revokeQurlsButton.disabled = (page?.access_grants || []).length === 0;
  renderRevokedGuests();

  if (!grants.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state compact";
    empty.textContent =
      "No immediate-access invitations. Scheduled guests appear below.";
    grantList.appendChild(empty);
    return;
  }

  grants.forEach((grant) => {
    const card = document.createElement("article");
    card.className = "grant-card";

    const copy = document.createElement("div");
    copy.className = "grant-copy";

    const heading = document.createElement("strong");
    heading.textContent = grant.label || "Unnamed guest";

    const details = document.createElement("span");
    details.textContent =
      `${grant.lifetime || "Custom"} · expires ${formatExpiry(grant.expires_at)}` +
      (grant.one_time_use ? " · one-time use" : "") +
      (grant.verification_required ? " · Email verification required" : "");

    copy.append(heading, details);

    const actions = document.createElement("div");
    actions.className = "grant-actions";

    const copyButton = document.createElement("button");
    copyButton.type = "button";
    copyButton.className = "secondary";
    copyButton.textContent = "Copy guest link";
    copyButton.addEventListener("click", () => {
      copyText(grant.qurl_link, copyButton).catch((error) => {
        setStatus(`Copy failed: ${error.message}`, "error");
      });
    });

    const revokeButton = document.createElement("button");
    revokeButton.type = "button";
    revokeButton.className = "danger";
    revokeButton.textContent = "Revoke this link";
    revokeButton.addEventListener("click", () => {
      revokeGrant(grant).catch((error) => {
        setStatus(`Error: ${error.message}`, "error");
      });
    });

    const activityButton = document.createElement("button");
    activityButton.type = "button";
    activityButton.className = "secondary";
    activityButton.textContent = "View activity";
    activityButton.addEventListener("click", () => {
      openGuestActivity(grant.id).catch((error) => {
        setStatus(`Error: ${error.message}`, "error");
      });
    });

    actions.appendChild(activityButton);
    if (grant.qurl_link) {
      actions.append(copyButton, finishedSharingButton(page.id, grant));
    } else {
      const shared = document.createElement("span");
      shared.textContent = sharedInvitationStatus;
      copy.appendChild(shared);
    }
    actions.appendChild(revokeButton);
    card.append(copy, actions);
    grantList.appendChild(card);
  });
}

function renderRevokedGuests() {
  const revoked = activityGuests.filter((guest) => guest.revoked_at && !guest.scheduled_guest_id);
  const scheduledEnded = scheduleData.page_id === currentPage?.id ? document.getElementById("ended-scheduled-list").children.length : 0;
  revokedCount.textContent = String(revoked.length + scheduledEnded);
  revokedList.replaceChildren();

  if (!revoked.length && scheduledEnded) return;
  if (!revoked.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state compact";
    empty.textContent = "No retained revoked-guest history.";
    revokedList.appendChild(empty);
    return;
  }

  revoked.forEach((guest) => {
    const expired = pageSecurityEvents.some(
      (entry) => entry.grant_id === guest.grant_id &&
        entry.event_type === "guest_access_expired",
    );
    const card = document.createElement("article");
    card.className = "grant-card revoked-grant";
    const copy = document.createElement("div");
    copy.className = "grant-copy";
    const heading = document.createElement("strong");
    heading.textContent = guest.label || "Unnamed guest";
    const details = document.createElement("span");
    details.textContent =
      `${expired ? "Expired" : "Revoked"} ${formatExpiry(guest.revoked_at)} · ` +
      `${guest.action_count} action${guest.action_count === 1 ? "" : "s"}`;
    copy.append(heading, details);

    const viewButton = document.createElement("button");
    viewButton.type = "button";
    viewButton.className = "secondary";
    viewButton.textContent = "View activity";
    viewButton.addEventListener("click", () => {
      openGuestActivity(guest.grant_id).catch((error) => {
        setStatus(`Error: ${error.message}`, "error");
      });
    });
    card.append(copy, viewButton);
    revokedList.appendChild(card);
  });
}

function securityEventDescription(entry) {
  const details = entry.details || {};
  const guest = entry.guest_label ? ` · ${entry.guest_label}` : "";
  const context = [
    details.resource_id,
    details.action_id && humanize(details.action_id),
  ].filter(Boolean).join(" · ");
  return {
    title: `${entry.event_type === "home_assistant_action_rejected"
      ? "The action could not be confirmed. Check the current state before trying again."
      : humanize(entry.event_type)}${guest}`,
    context: context || humanize(details.reason || "Gateway protection"),
  };
}

function renderSecurityEvents() {
  securityEventCount.textContent = String(pageSecurityEvents.length);
  securityEventList.replaceChildren();
  if (!pageSecurityEvents.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state compact";
    empty.textContent = "No security events recorded for this page.";
    securityEventList.appendChild(empty);
    return;
  }
  pageSecurityEvents.forEach((entry) => {
    const description = securityEventDescription(entry);
    const row = document.createElement("article");
    row.className = "activity-entry security-event-entry";
    const heading = document.createElement("strong");
    heading.textContent = description.title;
    const metadata = document.createElement("span");
    metadata.textContent = formatExpiry(entry.occurred_at);
    const context = document.createElement("small");
    context.textContent = description.context;
    row.append(heading, metadata, context);
    securityEventList.appendChild(row);
  });
}

async function loadGuestActivitySummaries(pageId) {
  const response = await adminApi.fetch(
    `api/admin/pages/${encodeURIComponent(pageId)}/activity`,
    {cache: "no-store"},
  );
  const data = await responseJson(response, "Could not load guest activity");
  if (!response.ok) {
    throw new Error(data.error || "Could not load guest activity");
  }
  activityGuests = data.guests || [];
  pageSecurityEvents = data.security_events || [];
  renderSecurityEvents();
}

function activityParameters(parameters) {
  const entries = Object.entries(parameters || {});
  return entries.length
    ? entries.map(([key, value]) => `${humanize(key)}: ${value}`).join(" · ")
    : "No parameters";
}

async function openGuestActivity(grantId) {
  if (!currentPage) return;
  const response = await adminApi.fetch(
    `api/admin/pages/${encodeURIComponent(currentPage.id)}/activity/` +
      encodeURIComponent(grantId),
    {cache: "no-store"},
  );
  const data = await responseJson(response, "Could not load guest activity");
  if (!response.ok) {
    throw new Error(data.error || "Could not load guest activity");
  }

  selectedActivityGuest = data.guest;
  activityTitle.textContent = data.guest.label || "Unnamed guest";
  const expired = (data.security_events || []).some(
    (entry) => entry.event_type === "guest_access_expired",
  );
  activitySummary.textContent = data.guest.revoked_at
    ? `${expired ? "Expired" : "Revoked"} ${formatExpiry(data.guest.revoked_at)}. History is automatically deleted after 30 days.`
    : `Active access · expires ${formatExpiry(data.guest.expires_at)}.`;
  deleteActivityButton.classList.toggle(
    "hidden",
    !data.guest.revoked_at,
  );
  activityList.replaceChildren();

  if (!data.actions.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state compact";
    empty.textContent = "No actions recorded for this guest.";
    activityList.appendChild(empty);
  } else {
    data.actions.forEach((entry) => {
      const row = document.createElement("article");
      row.className = `activity-entry ${entry.outcome}`;
      const heading = document.createElement("strong");
      heading.textContent = `${entry.entity_name} · ${humanize(entry.action_id)}`;
      const metadata = document.createElement("span");
      metadata.textContent =
        `${formatExpiry(entry.occurred_at)} · ${entry.outcome}`;
      const parameters = document.createElement("small");
      parameters.textContent = activityParameters(entry.parameters);
      row.append(heading, metadata, parameters);
      if (entry.error) {
        const error = document.createElement("small");
        error.className = "activity-error";
        error.textContent = entry.error === "Home Assistant rejected the action"
          ? "The action could not be confirmed. Check the current state before trying again."
          : entry.error;
        row.appendChild(error);
      }
      activityList.appendChild(row);
    });
  }
  (data.security_events || []).forEach((entry) => {
    const description = securityEventDescription(entry);
    const row = document.createElement("article");
    row.className = "activity-entry security-event-entry";
    const heading = document.createElement("strong");
    heading.textContent = description.title;
    const metadata = document.createElement("span");
    metadata.textContent = formatExpiry(entry.occurred_at);
    const context = document.createElement("small");
    context.textContent = description.context;
    row.append(heading, metadata, context);
    activityList.appendChild(row);
  });
  activityDialog.showModal();
}

async function deleteSelectedActivity() {
  if (!currentPage || !selectedActivityGuest?.revoked_at) return;
  if (!await confirmAction(
    "Permanently delete this revoked guest and all of their activity history?",
  )) {
    return;
  }
  const response = await adminApi.fetch(
    `api/admin/pages/${encodeURIComponent(currentPage.id)}/activity/` +
      encodeURIComponent(selectedActivityGuest.grant_id),
    {method: "DELETE"},
  );
  const data = await responseJson(response, "Could not delete guest record");
  if (!response.ok) {
    throw new Error(data.error || "Could not delete guest record");
  }
  activityDialog.close();
  selectedActivityGuest = null;
  await loadGuestActivitySummaries(currentPage.id);
  renderAccessGrants(currentPage);
  setStatus("Revoked guest and activity history deleted.", "success");
}

// Track actual form values, so reverting an edit is clean and previews never save.
const guestDrafts = new WeakMap();
function guestInputs(dialog) {
  return [...document.querySelectorAll(`#${dialog.id} input, #${dialog.id} select`)];
}
function guestSnapshot(dialog) {
  return JSON.stringify(guestInputs(dialog).map(input => [input.id || input.name, input.value, Boolean(input.checked)]));
}
function rememberGuestDraft(dialog) {
  guestDrafts.set(dialog, {baseline: guestSnapshot(dialog), busy: false, closing: false});
}
function setGuestBusy(dialog, busy) {
  const state = guestDrafts.get(dialog);
  if (!state) return;
  state.busy = busy;
  if (busy) {
    state.controls = [...guestInputs(dialog), ...document.querySelectorAll(`#${dialog.id} button`)];
    state.disabled = state.controls.map(input => input.disabled);
    state.controls.forEach(input => { input.disabled = true; });
  } else {
    state.controls?.forEach((input, i) => { input.disabled = state.disabled[i]; });
  }
}
function guestSaved(dialog) {
  const state = guestDrafts.get(dialog);
  if (state) state.baseline = guestSnapshot(dialog);
}
async function requestGuestClose(dialog) {
  const state = guestDrafts.get(dialog);
  if (state?.busy || state?.closing) return false;
  if (state && state.baseline !== guestSnapshot(dialog)) {
    state.closing = true;
    const discard = await confirmAction("Your guest changes have not been saved. Discard them and close?", {
      title: "Discard unsaved changes?", acceptLabel: "Discard changes", safeDefault: true,
    });
    state.closing = false;
    if (!discard) return false;
  }
  dialog.close();
  return true;
}
function clearGuestErrors(dialog) {
  for (const element of document.querySelectorAll(`#${dialog.id} .guest-field-error`)) {
    element.classList.remove("guest-field-error");
    element.removeAttribute("aria-invalid");
    const described = (element.getAttribute("aria-describedby") || "").split(" ").filter(id => id && id !== `${element.id}-error`);
    if (described.length) element.setAttribute("aria-describedby", described.join(" "));
    else element.removeAttribute("aria-describedby");
  }
  for (const note of document.querySelectorAll(`#${dialog.id} .guest-field-message`)) note.remove();
}
function guestInputError(message, fields = []) {
  return Object.assign(new Error(message), {fields});
}
function showGuestError(dialog, status, error) {
  clearGuestErrors(dialog);
  status.textContent = error.message;
  status.className = "status error guest-form-error";
  status.setAttribute("role", "alert");
  status.setAttribute("aria-live", "assertive");
  const fields = (error.fields || []).map(id => document.getElementById(id));
  for (const field of fields) {
    field.classList.add("guest-field-error"); field.setAttribute("aria-invalid", "true");
    const note = document.createElement("small"); note.id = `${field.id}-error`;
    note.className = "guest-field-message wide"; note.textContent = error.message;
    field.setAttribute("aria-describedby", [field.getAttribute("aria-describedby"), note.id].filter(Boolean).join(" "));
    field.insertAdjacentElement("afterend", note);
  }
  const first = fields[0];
  const focus = first?.querySelector?.("input, select") || first || status;
  focus.focus(); (first || status).scrollIntoView({block: "center", behavior: "smooth"});
}
function setScheduleStatus(message, kind = "") {
  scheduleFormStatus.textContent = message;
  scheduleFormStatus.className = `status ${kind}`;
  scheduleFormStatus.setAttribute("role", "status");
  scheduleFormStatus.setAttribute("aria-live", "polite");
}
function validateScheduleInputs() {
  for (const input of guestInputs(scheduleDialog)) {
    if (!input.closest?.(".hidden") && input.willValidate && !input.checkValidity()) {
      throw guestInputError(input.validationMessage, [input.id]);
    }
  }
  const d = scheduleFields();
  if (!d.label.trim()) throw guestInputError("Enter a guest name.", ["schedule-name"]);
  if (d.kind === "weekly" && !d.weekdays.length) throw guestInputError("Choose at least one day of the week.", ["schedule-weekdays"]);
  if (d.first_date && d.last_date && d.last_date < d.first_date) throw guestInputError("The last date must be on or after the first date.", ["schedule-first", "schedule-last"]);
  const minutes = value => Number(value.slice(0, 2)) * 60 + Number(value.slice(3));
  const duration = minutes(d.end_time) - minutes(d.start_time) + (d.next_day ? 1440 : 0);
  if (duration < 2 || duration > 1440) throw guestInputError("Access must last 2 minutes to 24 hours. Select Ends next day for overnight access.", ["schedule-start", "schedule-end", "schedule-next-day"]);
  if (Boolean(d.notifications.targets.length) !== Boolean(d.notifications.events.length)) {
    throw guestInputError(d.notifications.targets.length
      ? "Choose at least one activity to be notified about, or turn off the alert destinations."
      : "Choose an alert destination, or turn off the selected activities.", ["schedule-alerts"]);
  }
}

function setUserDialogStatus(message, kind = "", fields = []) {
  if (kind === "error") {
    showGuestError(userDialog, userDialogStatus, guestInputError(message, fields));
    return;
  }
  userDialogStatus.setAttribute("role", "status");
  userDialogStatus.setAttribute("aria-live", "polite");
  userDialogStatus.textContent = message;
  userDialogStatus.className = message ? `status ${kind}` : "status hidden";
}

function openUserDialog() {
  clearGuestErrors(userDialog);
  setUserDialogStatus("");
  qurlLabelInput.value = "";
  verificationRequiredInput.checked = false;
  sendInvitationInput.checked = false;
  activityNotificationsInput.checked = false;
  activityNotificationOptions.classList.add("hidden");
  oneTimeUseInput.checked = false;
  configureGuestOptions();
  verificationEmailInput.value = "";
  verificationEmailField.classList.add("hidden");
  qurlResult.classList.add("hidden");
  rememberGuestDraft(userDialog);
  userDialog.showModal();
  qurlLabelInput.focus();
}

async function generateQurl() {
  if (generateQurlButton.disabled) return;
  clearGuestErrors(userDialog);
  if (!currentPage || !editingExisting) {
    setUserDialogStatus("Save the page before generating a qURL.", "error");
    return;
  }

  if (!layerVApiConfigured) {
    setUserDialogStatus(
      "LayerV API is not configured. Add LAYERV_API_TOKEN to .env.",
      "error",
    );
    return;
  }

  const userName = qurlLabelInput.value.trim();
  if (!userName) {
    setUserDialogStatus("Enter a guest name before creating the link.", "error", ["qurl-label"]);
    qurlLabelInput.focus();
    return;
  }

  const verificationRequested = verificationRequiredInput.checked;
  const invitationRequested = verificationRequested || sendInvitationInput.checked;
  const verificationEmail = verificationEmailInput.value.trim();
  const notificationSettings = activityNotificationsInput.checked ? {
    targets: [...document.querySelectorAll('input[name="notification-target"]:checked')].map((input) => input.value),
    events: [...document.querySelectorAll('input[name="notification-event"]:checked')].map((input) => input.value),
  } : null;
  if (activityNotificationsInput.checked && !notificationSettings.targets.length) {
    setUserDialogStatus("Choose a configured email or mobile notification target.", "error", ["notification-target-field"]);
    activityNotificationOptions.classList.remove("hidden");
    return;
  }
  if (activityNotificationsInput.checked && !notificationSettings.events.length) {
    setUserDialogStatus("Choose at least one guest activity to be notified about.", "error", ["notification-event-field"]);
    return;
  }

  if (invitationRequested && (!verificationEmail || !verificationEmailInput.checkValidity())) {
    setUserDialogStatus("Enter a valid email address for the invitation.", "error", ["verification-email"]);
    verificationEmailInput.focus();
    return;
  }

  let guestCreated = false;
  setGuestBusy(userDialog, true);
  generateQurlButton.disabled = true;
  setUserDialogStatus(`Creating access for ${userName}… Initial setup can take a few minutes.`);
  try {
    const lifetime = selectedLifetime();
    const duration = lifetime.match(/^([1-9][0-9]*)([mhd])$/);
    const lifetimeSeconds = duration
      ? Number(duration[1]) * {m: 60, h: 3600, d: 86400}[duration[2]]
      : 0;
    if (oneTimeUseInput.checked && lifetimeSeconds > 86400) {
      throw guestInputError("Single-use guest access supports at most 24 hours. Choose a shorter lifetime or turn off One-time use.", ["lifetime-fieldset", "one-time-use"]);
    }
    const response = await adminApi.fetch(
      `api/admin/pages/${encodeURIComponent(currentPage.id)}/qurls`,
      {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          label: userName,
          lifetime,
          one_time_use: oneTimeUseInput.checked,
          verification_required: verificationRequested,
          verification_email: verificationEmail,
          send_invitation: invitationRequested,
          invitation_email: verificationEmail,
          notifications: notificationSettings,
        }),
      },
    );
    const data = await responseJson(response, "Could not generate qURL");

    if (!response.ok) {
      throw new Error(data.error || "Could not generate qURL");
    }

    guestCreated = true;
    guestSaved(userDialog);
    currentPage.access_grants = [
      data.grant,
      ...(currentPage.access_grants || []),
    ];
    setGuestCountStatus(currentPage);

    qurlResult.replaceChildren();
    qurlResult.dataset.pageId = currentPage.id;
    qurlResult.dataset.grantId = data.grant.id;

    const activationLabel = document.createElement("strong");
    activationLabel.textContent = "Access Pages link";

    const activationLink = document.createElement("textarea");
    activationLink.className = "copy-value";
    activationLink.readOnly = true;
    activationLink.rows = 2;
    activationLink.value = data.grant.qurl_link;
    activationLink.setAttribute("aria-label", "Activation qURL");
    activationLink.addEventListener("focus", () => activationLink.select());

    const activationButton = document.createElement("button");
    activationButton.type = "button";
    activationButton.className = "secondary";
    activationButton.textContent = "Copy guest link";
    activationButton.addEventListener("click", () => {
      copyText(data.grant.qurl_link, activationButton).catch((error) => {
        setUserDialogStatus(`Copy failed: ${error.message}`, "error");
      });
    });

    const activationRow = document.createElement("div");
    activationRow.className = "qurl-result-row";
    activationRow.append(
      activationLabel,
      activationLink,
      activationButton,
    );

    const sharePanel = buildSharePanel(
      userName,
      data.grant.qurl_link,
    );
    const sharingContent = document.createElement("div");
    sharingContent.className = "qurl-sharing-content";
    sharingContent.append(activationRow, sharePanel);

    if (invitationRequested && data.email_delivery?.sent) {
      const deliveryStatus = document.createElement("div");
      deliveryStatus.className = "qurl-delivery-status";

      const deliveryTitle = document.createElement("strong");
      deliveryTitle.textContent = "Invitation email sent";
      const deliveryText = document.createElement("p");
      deliveryText.textContent =
        `The guest invitation was sent to ${verificationEmail}.` +
        (verificationRequested ? " A separate verification code will be sent when the guest opens the access page." : "");
      deliveryStatus.append(deliveryTitle, deliveryText);

      const fallback = document.createElement("details");
      fallback.className = "qurl-sharing-fallback";
      const fallbackSummary = document.createElement("summary");
      fallbackSummary.textContent = "Show backup sharing options";
      fallback.append(fallbackSummary, sharingContent);
      qurlResult.append(deliveryStatus, fallback);
    } else {
      if (invitationRequested) {
        const deliveryStatus = document.createElement("div");
        deliveryStatus.className = "qurl-delivery-status warning";
        const deliveryTitle = document.createElement("strong");
        deliveryTitle.textContent = "Invitation email was not sent";
        const deliveryText = document.createElement("p");
        deliveryText.textContent =
          "The guest link was created. Use a backup sharing option below, " +
          "then check the email configuration before sending another invitation.";
        deliveryStatus.append(deliveryTitle, deliveryText);
        qurlResult.append(deliveryStatus);
      }
      qurlResult.append(sharingContent);
    }
    qurlResult.appendChild(finishedSharingButton(currentPage.id, data.grant));
    qurlResult.classList.remove("hidden");
    qurlResult.classList.remove("result-reveal");
    void qurlResult.offsetWidth;
    qurlResult.classList.add("result-reveal");
    window.requestAnimationFrame(() => {
      qurlResult.scrollIntoView({behavior: "smooth", block: "nearest"});
      qurlResult.focus({preventScroll: true});
    });

    qurlLabelInput.value = "";
    guestSaved(userDialog);
    await loadPages();
    await loadGuestActivitySummaries(currentPage.id);
    renderAccessGrants(currentPage);
    if (invitationRequested && data.email_delivery?.sent) {
      setUserDialogStatus(
        `Invitation sent for ${userName}. Access expires ${formatExpiry(data.grant.expires_at)}.`,
        "success",
      );
    } else if (invitationRequested) {
      setUserDialogStatus(
        `Guest link created for ${userName}, but the invitation email was not sent.`,
        "error",
      );
    } else {
      setUserDialogStatus(
        `Guest link created for ${userName}. The page connector is waking and should be ready in a few seconds. Access expires ${formatExpiry(data.grant.expires_at)}.`,
        "success",
      );
    }
  } catch (error) {
    setGuestBusy(userDialog, false);
    setUserDialogStatus(guestCreated ? `Guest link created, but the display could not finish updating: ${error.message}` : `Error: ${error.message}`, "error", error.fields || []);
  } finally {
    setGuestBusy(userDialog, false);
    generateQurlButton.disabled = false;
  }
}

async function revokeGrant(grant) {
  if (!currentPage || !editingExisting) return;

  const name = grant.label || "this access link";
  const confirmed = await confirmAction(
    `Revoke ${name}? This guest's gateway access and LayerV qURL will stop working.`,
  );
  if (!confirmed) return;

  const response = await adminApi.fetch(
    `api/admin/pages/${encodeURIComponent(currentPage.id)}/qurls/${encodeURIComponent(grant.id)}`,
    {
      method: "DELETE",
    },
  );
  const data = await responseJson(response, "Could not revoke access link");
  if (!response.ok) {
    if (data.local_access_revoked) {
      currentPage.access_grants = (currentPage.access_grants || []).filter(
        (item) => item.id !== grant.id,
      );
      await loadPages();
      await loadGuestActivitySummaries(currentPage.id);
      renderAccessGrants(currentPage);
      setStatus(
        `Gateway access was revoked, but LayerV revocation failed: ${
          data.remote_error || data.error || "unknown error"
        }`,
        "error",
      );
      return;
    }
    throw new Error(data.error || "Could not revoke access link");
  }

  currentPage.access_grants = (currentPage.access_grants || []).filter(
    (item) => item.id !== grant.id,
  );
  await loadPages();
  await loadGuestActivitySummaries(currentPage.id);
  renderAccessGrants(currentPage);
  setStatus(
    data.remote_revocation_pending
      ? "Gateway access is revoked. LayerV revocation is queued after a 15-second status-update window."
      : "This gateway token and LayerV qURL have been revoked. Other links are unchanged.",
    "success",
  );
}

async function revokeAllQurls() {
  if (!currentPage || !editingExisting) return;

  const confirmed = await confirmAction(
    "Revoke every gateway token and pause scheduled invitations for this page? Gateway access stops immediately; LayerV revocation follows after a short status-update window.",
  );
  if (!confirmed) return;

  revokeQurlsButton.disabled = true;
  setStatus("Revoking page access…");

  let locallyRevoked = false;
  try {
    const response = await adminApi.fetch(
      `api/admin/pages/${encodeURIComponent(currentPage.id)}/qurls`,
      {
        method: "DELETE",
      },
    );
    const data = await responseJson(response, "Could not revoke access");

    if (!response.ok && !data.local_access_revoked) {
      throw new Error(data.error || "Could not revoke access");
    }

    locallyRevoked = true;
    currentPage.access_grants = [];
    qurlResult.classList.add("hidden");
    await loadPages();
    await loadGuestActivitySummaries(currentPage.id);
    renderAccessGrants(currentPage);
    const failures = data.remote_failures?.length || 0;
    const pending = data.remote_revocation_pending_count || 0;
    const summary = `Revoked ${data.revoked_count} access link${data.revoked_count === 1 ? "" : "s"} locally.`;
    setStatus(
      summary + (failures
        ? " Remote revocation is not confirmed. Check the connection and cleanup status."
        : pending ? " Remote revocation is queued." : " Remote revocation confirmed."),
      failures || pending ? "warning" : "success",
    );
  } catch (error) {
    setStatus(`${locallyRevoked ? "Access revoked locally. Could not refresh the guest list: " : "Error: "}${error.message}`, "error");
  } finally {
    revokeQurlsButton.disabled = false;
  }
}

function prepareEditor(page, existing) {
  currentPage = page;
  editingExisting = existing;
  idWasManuallyEdited = existing;

  titleInput.value = page.title;
  pageIdInput.value = page.id;
  pageIdInput.disabled = existing;
  descriptionInput.value = page.description || "";
  proximityEnabledInput.checked = Boolean(page.proximity?.enabled);
  proximityRadiusInput.value = page.proximity?.radius_meters || 500;
  proximityRadiusField.classList.toggle(
    "hidden",
    !proximityEnabledInput.checked,
  );

  deleteButton.classList.toggle("hidden", !existing);
  previewLink.classList.toggle("hidden", !existing);
  editorUsersButton.classList.toggle("hidden", !existing);
  editorUsersBottomButton.classList.toggle("hidden", !existing);
  previewLink.removeAttribute("href");

  loadSelections(page);
  updateSelectionSummary();
  renderCatalog();
  showEditor();

  setStatus(
    existing
      ? `Editing “${page.title}”.`
      : "Create a page and choose the controls it should expose.",
  );
}

function setGuestCountStatus(page) {
  const count = (page.access_grants || []).length;
  setStatus(
    `${count} ${count === 1 ? "guest" : "guests"} configured for “${page.title}”.`,
    "success",
  );
}

async function manageUsers(pageId) {
  expandedScheduledGuests.clear();
  setStatus("Loading guests…");

  try {
    const response = await adminApi.fetch(
      `api/admin/pages/${encodeURIComponent(pageId)}`,
      {
        cache: "no-store",
      },
    );
    const data = await responseJson(response, "Could not load page guests");

    if (!response.ok) {
      throw new Error(data.error || "Could not load page guests");
    }

    currentPage = data;
    editingExisting = true;
    usersTitle.textContent = data.title;
    qurlLabelInput.value = "";
    qurlResult.classList.add("hidden");
    await loadGuestActivitySummaries(data.id);
    renderAccessGrants(data);
    showUsers();
    await loadSchedules();
    setGuestCountStatus(data);
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  }
}

function createNewPage() {
  prepareEditor(blankPage(), false);
}

async function editPage(pageId) {
  setStatus("Loading page…");

  try {
    const response = await adminApi.fetch(
      `api/admin/pages/${encodeURIComponent(pageId)}`,
      {
        cache: "no-store",
      },
    );
    const data = await responseJson(response, "Could not load page");

    if (!response.ok) {
      throw new Error(data.error || "Could not load page");
    }

    await loadDiscovery(true);
    prepareEditor(data, true);
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  }
}

function buildPagePayload() {
  const entityMap = new Map(
    discovery.entities.map((entity) => [entity.entity_id, entity])
  );

  const resources = [];

  selectionOrder.forEach((entityId) => {
    const services = selections.get(entityId);
    if (!services) return;
    const entity = entityMap.get(entityId);
    if (!entity) {
      throw new Error(`Saved entity ${entityId} is unavailable or excluded. Restore it or remove it before saving.`);
    }
    const availableServices = new Set(entity.actions.map((action) => action.service));
    const unsupported = [...services].filter((service) => service !== "view" && !availableServices.has(service));
    if (unsupported.length) {
      throw new Error(`Remove unsupported controls for ${entityId}: ${unsupported.join(", ")}.`);
    }
    const availableActions = [...entity.actions];
    if (services.has("view") && !availableServices.has("view")) {
      availableActions.push({service: "view", name: "Display"});
    }

    const actions = availableActions
      .filter((action) => services.has(action.service))
      .map((action) => ({
        id: action.service,
        name: action.name,
        service: action.service,
      }));

    if (!actions.length) return;

    const resource = {
      id: currentPage?.resources?.find((item) => item.entity_id === entity.entity_id)?.id
        || resourceId(entity.entity_id),
      name: (
        customNames.get(entity.entity_id) ||
        entity.name ||
        entity.entity_id
      ).trim(),
      entity_id: entity.entity_id,
      domain: entity.domain,
      actions,
    };
    if (entity.domain === "camera") {
      resource.camera_refresh_interval = cameraRefreshIntervals.get(entityId) ?? 30;
    }
    resources.push(resource);
  });

  return {
    id: pageIdInput.value.trim(),
    title: titleInput.value.trim(),
    description: descriptionInput.value.trim(),
    proximity: {
      enabled: proximityEnabledInput.checked,
      radius_meters: Number(proximityRadiusInput.value),
    },
    resources,
  };
}

proximityEnabledInput.addEventListener("change", () => {
  proximityRadiusField.classList.toggle(
    "hidden",
    !proximityEnabledInput.checked,
  );
});

async function savePage() {
  let payload;
  try {
    payload = buildPagePayload();
  } catch (error) {
    setStatus(error.message, "error");
    return;
  }

  if (!payload.title) {
    setStatus("Enter a page name.", "error");
    titleInput.focus();
    return;
  }

  if (!payload.id) {
    setStatus("Enter a page ID.", "error");
    pageIdInput.focus();
    return;
  }

  saveButton.disabled = true;
  saveBottomButton.disabled = true;
  setStatus("Saving page…");

  try {
    const endpoint = editingExisting
      ? `api/admin/pages/${encodeURIComponent(currentPage.id)}`
      : "api/admin/pages";

    const response = await adminApi.fetch(endpoint, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });

    const data = await responseJson(response, "Could not save page");

    if (!response.ok) {
      throw new Error(data.error || "Could not save page");
    }

    editingExisting = true;
    currentPage = data;
    pageIdInput.disabled = true;
    deleteButton.classList.remove("hidden");
    previewLink.classList.remove("hidden");
    previewLink.removeAttribute("href");

    await loadPages();
    prepareEditor(data, true);
    setStatus("Page saved.", "success");
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  } finally {
    saveButton.disabled = false;
    saveBottomButton.disabled = false;
  }
}

async function deletePage() {
  if (!currentPage || !editingExisting) return;

  const userCount = currentPage.access_grants?.length || 0;
  const confirmed = await confirmAction(
    `Delete the access page “${currentPage.title}”? ` +
    `${userCount} ${userCount === 1 ? "guest link" : "guest links"} will be revoked.`,
  );

  if (!confirmed) return;

  deleteButton.disabled = true;
  setStatus("Deleting page…");

  try {
    const response = await adminApi.fetch(
      `api/admin/pages/${encodeURIComponent(currentPage.id)}`,
      {
        method: "DELETE",
      },
    );
    const data = await responseJson(response, "Could not delete page");

    if (!response.ok && !data.page_deleted) {
      throw new Error(data.error || "Could not delete page");
    }

    await loadPages();
    showDashboard();
    renderPageList();
    if (data.policy_cleanup_pending) {
      setStatus("Page deleted and local access revoked. Policy cleanup is pending; remote revocation may still need attention.", "warning");
    } else if (data.remote_failures?.length) {
      setStatus(
        `Page deleted and local access revoked, but ${data.remote_failures.length} LayerV qURL ` +
        `${data.remote_failures.length === 1 ? "revocation" : "revocations"} failed.`,
        "error",
      );
    } else {
      setStatus(
        `Page deleted and ${userCount} ${userCount === 1 ? "guest link" : "guest links"} revoked.`,
        "success",
      );
    }
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  } finally {
    deleteButton.disabled = false;
  }
}

async function loadPages() {
  const response = await adminApi.fetch("api/admin/pages", {
    cache: "no-store",
  });
  const data = await responseJson(response, "Could not load pages");

  if (!response.ok) {
    if (response.status === 401) {
      throw new Error(
        "Valid admin token required. Open /admin?token=YOUR_ADMIN_TOKEN.",
      );
    }
    throw new Error(data.error || "Could not load pages");
  }

  pages = data.pages;
  updateGatewayCounts();
  layerVApiConfigured = Boolean(data.layerv_api_configured);
  qurlMaxLifetimeDays = Number(data.qurl_max_lifetime_days) || 30;
  configureLifetimeOptions();
  renderPageList();
}

async function loadDiscovery(force = false) {
  const response = await adminApi.fetch(
    force ? "api/admin/discovery?refresh=1" : "api/admin/discovery",
    {
    cache: "no-store",
    },
  );
  const data = await responseJson(response, "Discovery failed");

  if (!response.ok) {
    throw new Error(data.error || "Discovery failed");
  }

  discovery = data;
  renderPicker();
}

async function loadApplication() {
  setStatus("Loading pages and Home Assistant entities…");
  newPageButton.disabled = true;

  try {
    await Promise.all([loadPages(), loadDiscovery()]);
    await loadGatewayStatus();
    applicationReady = true;
    newPageButton.disabled = false;
    renderPageList();
    showDashboard();
    setStatus(
      `${pages.length} ${pages.length === 1 ? "page" : "pages"} configured. ` +
      `${discovery.entity_count} controllable Home Assistant entities available.`,
      "success",
    );
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  }
}

titleInput.addEventListener("input", () => {
  if (!editingExisting && !idWasManuallyEdited) {
    pageIdInput.value = slugify(titleInput.value);
  }
});

pageIdInput.addEventListener("input", () => {
  idWasManuallyEdited = true;
  pageIdInput.value = slugify(pageIdInput.value);
});

newPageButton.addEventListener("click", createNewPage);
backButton.addEventListener("click", showDashboard);
usersBackButton.addEventListener("click", showDashboard);
usersEditButton.addEventListener("click", () => {
  if (currentPage) editPage(currentPage.id);
});
usersPreviewButton.addEventListener("click", () => {
  if (!currentPage) return;
  openAdminPreview(currentPage.id).catch((error) => {
    setStatus(`Error: ${error.message}`, "error");
  });
});
editorUsersButton.addEventListener("click", () => {
  if (currentPage) manageUsers(currentPage.id);
});
editorUsersBottomButton.addEventListener("click", () => {
  if (currentPage) manageUsers(currentPage.id);
});
addUserButton.addEventListener("click", openGuestChoice);
closeUserDialogButton.addEventListener("click", () => requestGuestClose(userDialog));
closeActivityDialogButton.addEventListener(
  "click",
  () => activityDialog.close(),
);
deleteActivityButton.addEventListener("click", () => {
  deleteSelectedActivity().catch((error) => {
    setStatus(`Error: ${error.message}`, "error");
  });
});
activityDialog.addEventListener("click", (event) => {
  if (event.target === activityDialog) {
    activityDialog.close();
  }
});
saveButton.addEventListener("click", savePage);
saveBottomButton.addEventListener("click", savePage);
deleteButton.addEventListener("click", deletePage);
generateQurlButton.addEventListener("click", generateQurl);
revokeQurlsButton.addEventListener("click", revokeAllQurls);
openPickerButton.addEventListener("click", openPicker);
closePickerButton.addEventListener("click", () => pickerDialog.close());
pickerDoneButton.addEventListener("click", () => pickerDialog.close());
pickerSearchInput.addEventListener("input", renderPicker);
pickerTargetTab.addEventListener("click", () => {
  pickerBrowseMode = "target";
  activePickerCategory = null;
  pickerTargetTab.classList.add("active");
  pickerTargetTab.setAttribute("aria-selected", "true");
  pickerTypeTab.classList.remove("active");
  pickerTypeTab.setAttribute("aria-selected", "false");
  renderPicker();
});
pickerTypeTab.addEventListener("click", () => {
  pickerBrowseMode = "type";
  activePickerCategory = null;
  pickerTypeTab.classList.add("active");
  pickerTypeTab.setAttribute("aria-selected", "true");
  pickerTargetTab.classList.remove("active");
  pickerTargetTab.setAttribute("aria-selected", "false");
  renderPicker();
});
pickerDialog.addEventListener("click", (event) => {
  if (event.target === pickerDialog) {
    pickerDialog.close();
  }
});
userDialog.addEventListener("click", (event) => {
  if (event.target === userDialog) {
    requestGuestClose(userDialog);
  }
});
openResetDialogButton.addEventListener("click", () => {
  resetConfirmationInput.value = "";
  resetStatus.className = "status";
  resetStatus.textContent = "";
  confirmResetButton.disabled = true;
  resetDialog.showModal();
  resetConfirmationInput.focus();
});
closeResetDialogButton.addEventListener("click", () => resetDialog.close());
cancelResetButton.addEventListener("click", () => resetDialog.close());
resetConfirmationInput.addEventListener("input", () => {
  confirmResetButton.disabled = resetConfirmationInput.value !== "RESET";
});
confirmResetButton.addEventListener("click", resetLayerVConnection);
resetDialog.addEventListener("click", (event) => {
  if (event.target === resetDialog) {
    resetDialog.close();
  }
});

refreshButton.addEventListener("click", async () => {
  refreshButton.disabled = true;
  setStatus("Refreshing from Home Assistant…");

  try {
    await loadDiscovery(true);
    renderCatalog();
    setStatus(
      `Loaded ${discovery.entity_count} controllable entities.`,
      "success",
    );
  } catch (error) {
    setStatus(`Error: ${error.message}`, "error");
  } finally {
    refreshButton.disabled = false;
  }
});

loadApplication();

previewLink.addEventListener("click", (event) => {
  event.preventDefault();
  if (!currentPage?.id || !editingExisting) return;
  openAdminPreview(currentPage.id).catch((error) => {
    setStatus(`Error: ${error.message}`, "error");
  });
});

// Scheduled invitations have durable server-owned timing and delivery state.
let scheduleData = {schedules: [], guests: [], timezone: "UTC"};
const expandedScheduledGuests = new Set();
let editingSchedule = null;
const scheduleDialog = document.getElementById("schedule-dialog");
const guestChoiceDialog = document.getElementById("guest-choice-dialog");
const scheduleFormStatus = document.getElementById("schedule-form-status");
const scheduleValueFields = {
  label: "schedule-name", email: "schedule-email", kind: "schedule-kind",
  timezone: "schedule-timezone", date: "schedule-date", first_date: "schedule-first",
  last_date: "schedule-last", start_time: "schedule-start", end_time: "schedule-end",
};
const scheduleChecks = {
  next_day: "schedule-next-day", verification_required: "schedule-verification",
  one_time_use: "schedule-single-use",
};

async function openGuestChoice() {
  document.getElementById("add-schedule").disabled = true;
  document.getElementById("guest-schedule-help").textContent = "Checking scheduled access availability…";
  guestChoiceDialog.showModal();
  try { await loadSchedules(); }
  catch { document.getElementById("guest-schedule-help").textContent = "Could not check scheduling availability. Close and reopen Add guest to retry."; }
}

function scheduleFields() {
  const definition = {};
  for (const [key, id] of Object.entries(scheduleValueFields)) definition[key] = document.getElementById(id).value;
  for (const [key, id] of Object.entries(scheduleChecks)) definition[key] = document.getElementById(id).checked;
  definition.weekdays = [...document.querySelectorAll('input[name="schedule-weekday"]:checked')].map(x => Number(x.value));
  definition.notifications = {
    targets: [...document.querySelectorAll('input[name="schedule-target"]:checked')].map(x => x.value),
    events: [...document.querySelectorAll('input[name="schedule-event"]:checked')].map(x => x.value),
  };
  // Switching schedule kinds must not submit or validate hidden, inapplicable dates.
  if (definition.kind === "once") {
    definition.first_date = ""; definition.last_date = ""; definition.weekdays = [];
  } else {
    definition.date = "";
  }
  return definition;
}

function updateScheduleKind() {
  const weekly = document.getElementById("schedule-kind").value === "weekly";
  document.getElementById("schedule-date-field").classList.toggle("hidden", weekly);
  document.getElementById("schedule-date").required = !weekly;
  for (const id of ["schedule-weekdays", "schedule-first-field", "schedule-last-field"]) {
    document.getElementById(id).classList.toggle("hidden", !weekly);
  }
}

function scheduleTime(value, zone) {
  if (value == null) return "Daylight-saving boundary";
  return new Intl.DateTimeFormat(undefined, {timeZone: zone, dateStyle: "medium", timeStyle: "short"}).format(new Date(value * 1000));
}

function scheduleWindowText(window, zone) {
  if (window.start == null) return window.reason || "Daylight-saving boundary";
  const date = new Intl.DateTimeFormat(undefined, {timeZone: zone, dateStyle: "medium"});
  const time = new Intl.DateTimeFormat(undefined, {timeZone: zone, timeStyle: "short"});
  const start = new Date(window.start * 1000), end = new Date(window.end * 1000);
  const endDate = date.format(start) === date.format(end) ? "" : `${date.format(end)} · `;
  return `${date.format(start)} · ${time.format(start)}–${endDate}${time.format(end)} · ${zone}`;
}

function localScheduleTimezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || scheduleData.timezone || "UTC";
  } catch {
    return scheduleData.timezone || "UTC";
  }
}

function populateScheduleTimezones(selected) {
  const local = localScheduleTimezone();
  const select = document.getElementById("schedule-timezone");
  const zones = [...new Set([local, selected, scheduleData.timezone, "UTC", ...(scheduleData.timezones || [])].filter(Boolean))];
  select.replaceChildren();
  for (const zone of zones) {
    const option = document.createElement("option");
    option.value = zone;
    option.textContent = `${zone.replaceAll("_", " ")}${zone === local ? " (local)" : ""}`;
    select.append(option);
  }
  document.getElementById("schedule-timezone-help").textContent = `Local timezone: ${local}. Choose another zone if needed; saved schedules keep their timezone.`;
}

async function scheduleRequest(payload, id = editingSchedule) {
  const suffix = id ? `/${encodeURIComponent(id)}` : "";
  const response = await adminApi.fetch(`api/admin/pages/${encodeURIComponent(currentPage.id)}/schedules${suffix}`, {
    method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload),
  });
  const data = await responseJson(response, "Could not update schedule");
  if (!response.ok) throw new Error(data.error || "Could not update schedule");
  return data;
}

function selectScheduleGuest() {
  const id = document.getElementById("schedule-guest").value;
  const guest = (scheduleData.guests || []).find(row => row.id === id);
  const fixed = Boolean(guest && !editingSchedule);
  for (const field of ["schedule-name", "schedule-email"]) document.getElementById(field).readOnly = fixed;
  if (guest) {
    document.getElementById("schedule-name").value = guest.label;
    document.getElementById("schedule-email").value = guest.email;
  }
  document.getElementById("schedule-guest-help").textContent = editingSchedule
    ? "Name or email changes apply to this guest’s future schedules. Already-issued invitations keep their original recipient."
    : "Choose an existing guest to add another schedule to their timeline. Names and email addresses are never matched automatically.";
}

function openSchedule(row = null, duplicate = false) {
  editingSchedule = duplicate ? null : row?.id || null;
  const d = row?.definition || {
    label: "", email: "", kind: "once", timezone: localScheduleTimezone(),
    date: "", start_time: "09:00", end_time: "12:00", first_date: "", last_date: "",
    weekdays: [], next_day: false, verification_required: true, one_time_use: false,
    notifications: {targets: [], events: []},
  };
  populateScheduleTimezones(d.timezone);
  const guests = document.getElementById("schedule-guest");
  guests.replaceChildren();
  const fresh = document.createElement("option"); fresh.value = ""; fresh.textContent = "New guest"; guests.append(fresh);
  for (const guest of scheduleData.guests || []) {
    const option = document.createElement("option"); option.value = guest.id; option.textContent = `${guest.label} · ${guest.email}`; guests.append(option);
  }
  guests.value = row?.guest_id || "";
  guests.disabled = Boolean(editingSchedule);
  for (const [key, id] of Object.entries(scheduleValueFields)) document.getElementById(id).value = d[key] || "";
  selectScheduleGuest();
  for (const [key, id] of Object.entries(scheduleChecks)) document.getElementById(id).checked = Boolean(d[key]);
  for (const input of document.querySelectorAll('input[name="schedule-weekday"]')) input.checked = d.weekdays.includes(Number(input.value));
  for (const input of document.querySelectorAll('input[name="schedule-event"]')) input.checked = d.notifications.events.includes(input.value);
  const targets = document.getElementById("schedule-alert-targets");
  targets.replaceChildren();
  for (const option of registeredNotificationOptions) {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "checkbox"; input.name = "schedule-target"; input.value = option.value;
    input.checked = d.notifications.targets.includes(option.value);
    label.append(input, document.createTextNode(option.label)); targets.append(label);
  }
  document.getElementById("schedule-title").textContent = editingSchedule ? "Edit future invitations" : "Schedule guest";
  clearGuestErrors(scheduleDialog);
  setScheduleStatus(duplicate ? "Choose another date or time for this guest." : "");
  document.getElementById("schedule-preview").replaceChildren();
  updateScheduleKind();
  rememberGuestDraft(scheduleDialog);
  scheduleDialog.showModal();
}

async function previewSchedule() {
  clearGuestErrors(scheduleDialog);
  validateScheduleInputs();
  const definition = scheduleFields();
  const data = await scheduleRequest({action: "preview", definition});
  const preview = document.getElementById("schedule-preview");
  preview.replaceChildren();
  for (const window of data.upcoming) {
    const item = document.createElement("p"); item.textContent = scheduleWindowText(window, definition.timezone); preview.append(item);
  }
  if (!data.upcoming.length) throw guestInputError("No future occurrences. Choose a future unprocessed date or access window.", [document.getElementById("schedule-kind").value === "once" ? "schedule-date" : "schedule-last-field"]);
  setScheduleStatus(data.warning || "Review these times, then choose Save schedule. This preview has not saved your changes.");
  return data;
}

function scheduleRuleText(row) {
  const d = row.definition;
  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  const recurrence = d.kind === "weekly"
    ? (d.weekdays.length === 7 ? "Every day" : d.weekdays.map(day => days[day]).join(", "))
    : d.date;
  return `${recurrence} · ${d.start_time}–${d.end_time}${d.next_day ? " next day" : ""} · ${d.timezone}`;
}

function scheduleControl(label, callback) {
  const control = document.createElement("button");
  control.type = "button"; control.className = "secondary"; control.textContent = label;
  control.addEventListener("click", () => Promise.resolve().then(callback).catch(error => setStatus(error.message, "error")));
  return control;
}

function deliveryDescription(row) {
  if (row.accepted_at) return `Email accepted${row.state === "ended" ? " · Access ended" : row.state === "cancelled" ? " · Access cancelled" : ""}`;
  return {pending: "Waiting to create invitation", creating: "Creating invitation", created: "Invitation created",
    committing: "Preparing invitation", ready: "Email pending", sending: "Sending email", skipped: "Invitation skipped",
    failed: "Invitation failed", cancelled: "Invitation cancelled", ended: "Access ended"}[row.state] || row.state;
}

async function loadScheduledTimeline(state, more = false) {
  const request = ++state.request;
  const pageId = currentPage?.id;
  state.more.disabled = true;
  state.status.textContent = "Loading history…";
  if (!more) { state.cursor = null; state.entries.replaceChildren(); }
  try {
    const data = await scheduleRequest({action: "timeline", guest_id: state.guest.id,
      kind: state.filter.value, occurrence_id: state.occurrence, cursor: state.cursor}, null);
    if (request !== state.request || currentPage?.id !== pageId) return;
    for (const event of data.events) {
      const item = document.createElement("article"); item.className = "activity-entry";
      const title = document.createElement("strong");
      title.textContent = event.type === "delivery" ? `Invitation · ${deliveryDescription(event)}`
        : event.type === "action" ? `${event.title} · ${humanize(event.action_id)} · ${event.outcome}`
          : humanize(event.title);
      const when = document.createElement("span"); when.textContent = `${scheduleTime(event.at, event.timezone)} · ${event.timezone}`;
      const window = document.createElement("small"); window.textContent = `Access window: ${scheduleWindowText(event, event.timezone)}`;
      const detail = document.createElement("p");
      detail.textContent = event.type === "delivery"
        ? `${event.reason || ""} · Creation attempts: ${event.attempts || 0}; email attempts: ${event.email_attempts || 0}` +
          (event.due > Date.now() / 1000 ? ` · Retry: ${scheduleTime(event.due, event.timezone)}` : "")
        : [event.type === "action" ? activityParameters(event.details) : humanize(event.details?.reason || ""), event.error || ""].filter(Boolean).join(" · ");
      item.append(title, when, window, detail);
      if (!state.occurrence) item.append(scheduleControl("Show this access window", () => {
        state.occurrence = event.occurrence_id; state.clear.classList.remove("hidden");
        state.windowLabel.textContent = `Showing ${scheduleWindowText(event, event.timezone)}`;
        return loadScheduledTimeline(state);
      }));
      state.entries.append(item);
    }
    state.cursor = data.next_cursor;
    state.more.textContent = "Load older entries";
    state.more.classList.toggle("hidden", !state.cursor);
    state.status.textContent = state.entries.children.length ? "Newest first · Email acceptance does not confirm inbox delivery or a guest visit." : "No retained entries for this filter.";
  } catch (error) {
    if (request !== state.request || currentPage?.id !== pageId) return;
    state.status.textContent = error.message;
    state.more.textContent = "Retry loading history"; state.more.classList.remove("hidden");
  } finally { if (request === state.request) state.more.disabled = false; }
}

function renderScheduledGuests(data) {
  const list = document.getElementById("schedule-list"); list.replaceChildren();
  const endedList = document.getElementById("ended-scheduled-list"); endedList.replaceChildren();
  for (const guest of data.guests || []) {
    const rows = data.schedules.filter(row => row.guest_id === guest.id);
    const active = (data.active_invitations || []).filter(grant => data.scheduled_grants?.[grant.id] === guest.id && Date.parse(grant.expires_at) > Date.now());
    const ended = !active.length && rows.every(row => row.status === "revoked");
    const card = document.createElement("article"); card.className = "scheduled-guest";
    const key = `${currentPage.id}/${guest.id}`;
    const header = document.createElement("div"); header.className = "grant-card scheduled-guest-header";
    const copy = document.createElement("div"); copy.className = "grant-copy";
    const title = document.createElement("strong"); title.textContent = guest.label;
    const statuses = [...new Set(rows.map(row => row.status))];
    const contact = document.createElement("span");
    contact.textContent = `Scheduled · ${statuses.length ? statuses.map(humanize).join(" / ") : "Schedules removed"} · ${guest.email}`;
    const windows = rows.flatMap(row => (row.upcoming || []).filter(window => window.start != null).map(window => ({...window, timezone: row.definition.timezone}))).sort((a,b) => a.start-b.start);
    const next = document.createElement("span"); next.textContent = ended ? "Access ended · History retained" : windows.length ? `Next: ${scheduleWindowText(windows[0], windows[0].timezone)}` : "No upcoming access windows";
    copy.append(title, contact, next);
    if (!ended && (guest.needs_attention || statuses.includes("blocked"))) {
      const alert = document.createElement("span"); alert.className = "schedule-warning";
      alert.textContent = "Needs attention · View details"; copy.append(alert);
    }
    const body = document.createElement("div"); body.className = "scheduled-guest-body hidden";
    body.id = `scheduled-guest-details-${guest.id}`;
    const controls = document.createElement("div"); controls.className = "grant-actions";
    let loaded = false;
    const expand = scheduleControl("View details", () => {
      const open = expand.getAttribute("aria-expanded") !== "true";
      setExpanded(open);
      if (open && !loaded) { loaded = true; return loadScheduledTimeline(state); }
    });
    expand.setAttribute("aria-controls", body.id);
    expand.setAttribute("aria-label", `View details for ${guest.label}`);
    function setExpanded(open) {
      body.classList.toggle("hidden", !open);
      expand.setAttribute("aria-expanded", String(open));
      expand.textContent = open ? "Hide details" : "View details";
      expand.setAttribute("aria-label", `${open ? "Hide" : "View"} details for ${guest.label}`);
      if (open) expandedScheduledGuests.add(key); else expandedScheduledGuests.delete(key);
    }
    const revoke = scheduleControl("Revoke guest", async () => {
      if (!await confirmAction(`Revoke ${guest.label}? This ends all current access, stops all future schedules, and moves this guest to Recently ended guests. History is retained. You can explicitly resume schedules later.`)) return;
      revoke.disabled = true;
      try {
        await scheduleRequest({action: "revoke_guest", guest_id: guest.id}, null);
        await loadSchedules();
        setStatus("Guest revoked and moved to Recently ended guests. Current access and future invitations have stopped.", "success");
      } finally { revoke.disabled = false; }
    });
    revoke.className = "danger"; revoke.setAttribute("aria-label", `Revoke guest ${guest.label}`);
    controls.append(expand);
    if (!ended) controls.append(revoke);
    header.append(copy, controls); card.append(header);
    if (guest.latest_delivery) {
      const last = document.createElement("p"); last.textContent = `Last invitation: ${deliveryDescription(guest.latest_delivery)}`; body.append(last);
    }
    if (active.length) {
      title.textContent += ` · ${active.length} current invitation${active.length === 1 ? "" : "s"}`;
      const heading = document.createElement("h4"); heading.textContent = "Current invitations"; body.append(heading);
      for (const grant of active) {
        const line = document.createElement("p"); line.textContent = `Access ends ${formatExpiry(grant.expires_at)}`;
        body.append(line, scheduleControl("Revoke this invitation", async () => { await revokeGrant(grant); await loadSchedules(); }));
      }
    }
    for (const row of rows) {
      const section = document.createElement("section"); section.className = "guest-schedule";
      const heading = document.createElement("h4"); heading.textContent = `${scheduleRuleText(row)} · ${humanize(row.status)}`;
      section.append(heading);
      if (row.upcoming?.length) {
        const upcoming = document.createElement("details"), caption = document.createElement("summary");
        caption.textContent = "Upcoming access windows"; upcoming.append(caption);
        for (const window of row.upcoming) {
          const line = document.createElement("p"); line.textContent = scheduleWindowText(window, row.definition.timezone); upcoming.append(line);
        }
        section.append(upcoming);
      }
      const actions = document.createElement("div"); actions.className = "editor-actions";
      actions.append(scheduleControl("Edit", () => openSchedule(row)), scheduleControl(row.status === "enabled" ? "Pause" : "Resume", async () => {
        await scheduleRequest({action: row.status === "enabled" ? "pause" : "resume"}, row.id); await loadSchedules();
      }));
      const menu = document.createElement("details"); menu.className = "schedule-more";
      const caption = document.createElement("summary"); caption.textContent = "More"; menu.append(caption);
      const options = document.createElement("div"); options.className = "editor-actions";
      if (data.smtp_configured) options.append(scheduleControl("Duplicate schedule", () => openSchedule(row, true)));
      options.append(scheduleControl("Pause and end current access", async () => {
        if (!await confirmAction(`Pause this schedule for ${guest.label} and end its current access? Other schedules for this guest are unaffected.`)) return;
        await scheduleRequest({action: "pause", revoke_active: true}, row.id); await loadSchedules();
      }));
      const remove = scheduleControl("Delete schedule", async () => {
        if (!await confirmAction(`Delete this schedule for ${guest.label} (${scheduleRuleText(row)})? This stops its future invitations. Other schedules for this guest are unaffected. Already-issued invitations keep their original end time. History remains until its normal retention expires.`, {
          title: "Delete schedule?", acceptLabel: "Delete schedule", safeDefault: true,
        })) return;
        await scheduleRequest({action: "delete"}, row.id); await loadSchedules();
      });
      remove.className = "danger";
      actions.append(remove);
      menu.append(options); actions.append(menu); section.append(actions); body.append(section);
    }
    if (!rows.length) {
      const note = document.createElement("p"); note.textContent = "Schedules removed. Retained history and guest details are removed automatically after the retention period and cleanup finish."; body.append(note);
    }
    const heading = document.createElement("h4"); heading.textContent = "Activity and invitation history";
    const filter = document.createElement("select"); filter.setAttribute("aria-label", `History filter for ${guest.label}`);
    for (const [value, label] of [["all", "All activity and invitations"], ["activity", "Guest activity"], ["delivery", "Invitations and delivery"]]) {
      const option = document.createElement("option"); option.value = value; option.textContent = label; filter.append(option);
    }
    filter.value = "all";
    const entries = document.createElement("div"); entries.className = "activity-list";
    const status = document.createElement("p"); status.setAttribute("role", "status");
    const windowLabel = document.createElement("p");
    const state = {guest, filter, entries, status, windowLabel, occurrence: null, cursor: null, request: 0};
    const clear = scheduleControl("Show all access windows", () => {
      state.occurrence = null; windowLabel.textContent = ""; clear.classList.add("hidden"); return loadScheduledTimeline(state);
    }); clear.classList.add("hidden"); state.clear = clear;
    const more = scheduleControl("Load older entries", () => loadScheduledTimeline(state, Boolean(state.cursor))); state.more = more; more.classList.add("hidden");
    filter.addEventListener("change", () => loadScheduledTimeline(state));
    body.append(heading, filter, windowLabel, clear, entries, status, more); card.append(body); (ended ? endedList : list).append(card);
    setExpanded(expandedScheduledGuests.has(key));
    if (expandedScheduledGuests.has(key)) { loaded = true; loadScheduledTimeline(state); }
  }
  if (!list.children.length) list.textContent = "No scheduled guests. Use Add guest → Scheduled access.";
  renderRevokedGuests();
}

async function loadSchedules() {
  if (!currentPage) return;
  const pageId = currentPage.id;
  const response = await adminApi.fetch(`api/admin/pages/${encodeURIComponent(pageId)}/schedules`, {cache: "no-store"});
  const data = await responseJson(response, "Could not load schedules");
  if (!response.ok) throw new Error(data.error || "Could not load schedules");
  if (currentPage?.id !== pageId) return;
  scheduleData = {...data, page_id: pageId};
  document.getElementById("add-schedule").disabled = !data.smtp_configured || !data.supported;
  document.getElementById("guest-schedule-help").textContent = !data.supported
    ? "Scheduled access requires the Home Assistant App Connector."
    : !data.smtp_configured ? "Configure SMTP in Email settings to enable scheduled access."
      : "Scheduled invitations are emailed automatically when access begins.";
  document.getElementById("schedule-availability").textContent = !data.supported
    ? "Scheduling requires the Home Assistant App Connector."
    : !data.smtp_configured ? "Configure SMTP to enable scheduled invitations. Existing schedules remain visible."
      : "Expand a guest for schedules, delivery, and activity.";
  renderScheduledGuests(data);
  renderAccessGrants(currentPage);
}

document.getElementById("add-schedule").addEventListener("click", () => {
  guestChoiceDialog.close();
  openSchedule();
});
document.getElementById("add-guest-now").addEventListener("click", () => {
  guestChoiceDialog.close();
  openUserDialog();
});
document.getElementById("close-guest-choice").addEventListener("click", () => guestChoiceDialog.close());
guestChoiceDialog.addEventListener("click", event => {
  if (event.target === guestChoiceDialog) guestChoiceDialog.close();
});
document.getElementById("close-schedule").addEventListener("click", () => requestGuestClose(scheduleDialog));
document.getElementById("schedule-guest").addEventListener("change", selectScheduleGuest);
document.getElementById("schedule-kind").addEventListener("change", updateScheduleKind);
for (const id of ["schedule-date", "schedule-first", "schedule-last"]) {
  const input = document.getElementById(id);
  input.addEventListener("click", () => {
    try { input.showPicker?.(); }
    catch { /* Keep native activation and keyboard editing in restricted frames. */ }
  });
}
document.getElementById("preview-schedule").addEventListener("click", async () => {
  if (guestDrafts.get(scheduleDialog)?.busy) return;
  try {
    validateScheduleInputs();
    setGuestBusy(scheduleDialog, true);
    await previewSchedule();
  } catch (error) {
    setGuestBusy(scheduleDialog, false);
    showGuestError(scheduleDialog, scheduleFormStatus, error);
  }
  finally { setGuestBusy(scheduleDialog, false); }
});
document.getElementById("refresh-schedules").addEventListener("click", () => loadSchedules().catch(error => setStatus(error.message, "error")));
document.getElementById("pause-schedules").addEventListener("click", async () => {
  if (!await confirmAction("Pause future scheduled invitations for this page? Already-emailed invitations keep their original end.")) return;
  try { await scheduleRequest({action: "pause_all"}, null); await loadSchedules(); }
  catch (error) { setStatus(error.message, "error"); }
});
document.getElementById("schedule-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (guestDrafts.get(scheduleDialog)?.busy) return;
  try {
    validateScheduleInputs();
    setGuestBusy(scheduleDialog, true);
    const data = await previewSchedule();
    if (data.warning && !await confirmAction(data.warning)) return;
    const definition = scheduleFields();
    const guestId = document.getElementById("schedule-guest").value || null;
    const guest = scheduleData.guests?.find(item => item.id === guestId);
    if (editingSchedule && guest && (guest.label !== definition.label || guest.email !== definition.email) &&
        scheduleData.schedules.filter(row => row.guest_id === guestId).length > 1 &&
        !await confirmAction("Update this guest's contact details for all their future schedules on this Access Page? Already-issued invitations keep their original recipient.")) return;
    await scheduleRequest({action: "save", definition, guest_id: guestId});
    guestSaved(scheduleDialog);
    scheduleDialog.close();
    setStatus("Schedule saved. Invitations will be emailed when access begins.", "success");
  } catch (error) {
    setGuestBusy(scheduleDialog, false);
    showGuestError(scheduleDialog, scheduleFormStatus, error);
    return;
  }
  finally { setGuestBusy(scheduleDialog, false); }
  // Restore controls before refreshing: the owner may open another dialog meanwhile.
  try { await loadSchedules(); }
  catch { setStatus("Schedule saved, but the list could not refresh. Refresh schedules to see it.", "error"); }
});

for (const dialog of [userDialog, scheduleDialog]) {
  dialog.addEventListener("cancel", event => { event.preventDefault(); requestGuestClose(dialog); });
  if (dialog === scheduleDialog) dialog.addEventListener("click", event => {
    if (event.target === dialog) requestGuestClose(dialog);
  });
  dialog.addEventListener("input", () => {
    clearGuestErrors(dialog);
    const status = dialog === scheduleDialog ? scheduleFormStatus : userDialogStatus;
    if (status.classList.contains("error")) {
      status.textContent = ""; status.className = "status"; status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
    }
    if (dialog === scheduleDialog) {
      document.getElementById("schedule-preview").replaceChildren();
      setScheduleStatus("");
    }
  });
}
