import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"


class FrontendAssetTests(unittest.TestCase):
    def test_guest_link_sharing_stays_local_and_compose_only(self):
        html = (STATIC / "admin.html").read_text(encoding="utf-8")
        javascript = (STATIC / "admin.js").read_text(encoding="utf-8")
        qr_encoder = (
            STATIC / "vendor" / "qrcodegen.js"
        ).read_text(encoding="utf-8")
        provenance = (
            STATIC / "vendor" / "README.md"
        ).read_text(encoding="utf-8")

        self.assertIn(
            '<script src="static/vendor/qrcodegen.js" defer></script>',
            html,
        )
        self.assertIn(
            '<script type="module" src="static/admin.js"></script>',
            html,
        )
        self.assertIn("Project Nayuki. (MIT License)", qr_encoder)
        self.assertIn(
            "2c9044de6b049ca25cb3cd1649ed7e27aa055138",
            provenance,
        )
        self.assertIn("window.qrcodegen.QrCode.encodeText", javascript)
        self.assertIn("navigator.share", javascript)
        self.assertIn("if (!navigator.share)", javascript)
        self.assertIn('document.createElement("a")', javascript)
        self.assertIn('emailLink.target = "_top"', javascript)
        self.assertIn('smsLink.target = "_top"', javascript)
        self.assertIn("`mailto:", javascript)
        self.assertIn("smsLink.href = `sms:${recipient}`", javascript)
        self.assertNotIn("sms:${recipient}?&body=", javascript)
        self.assertIn("does not send or store recipients", javascript)
        self.assertNotIn("fetch(\"mailto:", javascript)
        self.assertNotIn("fetch(\"sms:", javascript)

    def test_guest_client_handles_revoked_plain_text_responses(self):
        javascript = (STATIC / "access.js").read_text(encoding="utf-8")

        self.assertIn("await response.text()", javascript)
        self.assertIn("class AccessEndedError extends Error", javascript)
        self.assertIn("accessEndedStatuses = [401, 410]", javascript)
        self.assertIn("[401, 403, 404, 410]", javascript)
        self.assertIn(
            "This access link has expired or been revoked.",
            javascript,
        )
        self.assertNotIn("await response.json()", javascript)

    def test_frontend_api_access_is_separated_into_modules(self):
        admin = (STATIC / "admin.js").read_text(encoding="utf-8")
        admin_api = (STATIC / "admin-api.js").read_text(encoding="utf-8")
        access = (STATIC / "access.js").read_text(encoding="utf-8")
        access_api = (STATIC / "access-api.js").read_text(encoding="utf-8")
        access_html = (STATIC / "access.html").read_text(encoding="utf-8")

        self.assertIn('from "./admin-api.js"', admin)
        self.assertIn('headers.set("X-Admin-Token", adminToken)', admin_api)
        self.assertNotIn("window.fetch(", admin)
        self.assertIn('from "./access-api.js"', access)
        self.assertIn("window.fetch(", access_api)
        self.assertNotIn("window.fetch(", access)
        self.assertIn(
            '<script type="module" src="/static/access.js"></script>',
            access_html,
        )

    def test_admin_confirmations_work_inside_home_assistant_ingress(self):
        javascript = (STATIC / "admin.js").read_text(encoding="utf-8")
        html = (STATIC / "admin.html").read_text(encoding="utf-8")

        self.assertNotIn("window.confirm", javascript)
        self.assertIn("await confirmAction(", javascript)
        self.assertIn('id="confirm-dialog"', html)
        self.assertIn('id="accept-confirm"', html)

    def test_action_denials_do_not_look_like_revoked_access(self):
        """Keep a command failure from falsely ending a valid guest session."""
        javascript = (STATIC / "access.js").read_text(encoding="utf-8")
        run_action = re.search(
            r"async function runAction\((?P<body>.*?)^\}",
            javascript,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(run_action)
        self.assertIn(
            'responseError(response, data, "Command failed")',
            run_action.group("body"),
        )
        self.assertNotIn(
            "[401, 403, 404, 410]",
            run_action.group("body"),
        )

    def test_guest_client_clears_stale_state_when_access_ends(self):
        """Remove previously authorized state after revocation or expiry."""
        javascript = (STATIC / "access.js").read_text(encoding="utf-8")
        end_access = re.search(
            r"function endAccess\(\) \{(?P<body>.*?)^\}",
            javascript,
            re.MULTILINE | re.DOTALL,
        )

        self.assertIsNotNone(end_access)
        self.assertIn("invalidateState()", end_access.group("body"))
        clear_controls = re.search(
            r"function clearCachedControls\(\) \{(?P<body>.*?)^\}",
            javascript,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(clear_controls)
        self.assertIn(
            "resources.replaceChildren()",
            clear_controls.group("body"),
        )
        self.assertIn(
            "parameterDrafts.clear()",
            clear_controls.group("body"),
        )

    def test_camera_refresh_is_per_resource_and_manual_capable(self):
        admin = (STATIC / "admin.js").read_text(encoding="utf-8")
        access = (STATIC / "access.js").read_text(encoding="utf-8")
        self.assertIn('refreshLabel.textContent = "Still-image refresh"', admin)
        self.assertIn("resource.camera_refresh_interval", admin)
        self.assertIn("resource.camera_refresh_interval ?? 30", access)
        self.assertIn('refreshButton.textContent = "Refresh image"', access)
        self.assertIn("frame.interval <= 0 || document.hidden", access)
        self.assertIn("    schedule();\n  }\n\n  const figure", access)
        self.assertIn("clearTimeout(frame.timer)", access)
        self.assertNotIn("CAMERA_REFRESH_INTERVAL_MS", access)

    def test_lifetime_radios_are_anchored_to_their_labels(self):
        html = (STATIC / "admin.html").read_text(encoding="utf-8")
        stylesheet = (STATIC / "admin.css").read_text(encoding="utf-8")

        choices = re.findall(
            r'<label><input type="radio" name="lifetime" '
            r'value="([^"]+)"',
            html,
        )
        self.assertEqual(
            choices,
            ["1h", "6h", "24h", "3d", "7d", "30d", "custom"],
        )
        label_rule = re.search(
            r"\.lifetime-options label \{(?P<body>.*?)\}",
            stylesheet,
            re.DOTALL,
        )
        input_rule = re.search(
            r"\.lifetime-options input \{(?P<body>.*?)\}",
            stylesheet,
            re.DOTALL,
        )
        self.assertIsNotNone(label_rule)
        self.assertIsNotNone(input_rule)
        self.assertIn("position: relative", label_rule.group("body"))
        self.assertIn("width: 1px", input_rule.group("body"))
        self.assertIn("height: 1px", input_rule.group("body"))

    def test_mobile_read_only_resources_keep_primary_state_visible(self):
        javascript = (STATIC / "access.js").read_text(encoding="utf-8")
        stylesheet = (STATIC / "access.css").read_text(encoding="utf-8")

        self.assertIn('card.classList.add("read-only-resource")', javascript)
        self.assertIn(
            'card.classList.add("compact-read-only-resource")',
            javascript,
        )
        self.assertIn(
            ".compact-read-only-resource .entity-state strong",
            stylesheet,
        )
        self.assertNotIn('readOnly.textContent = "Read-only"', javascript)

    def test_javascript_dom_ids_exist_in_matching_html(self):
        for stem in ("admin", "access"):
            javascript = (STATIC / f"{stem}.js").read_text(encoding="utf-8")
            html = (STATIC / f"{stem}.html").read_text(encoding="utf-8")
            ids = set(re.findall(r'getElementById\("([^"]+)"\)', javascript))

            for element_id in ids:
                self.assertIn(
                    f'id="{element_id}"',
                    html,
                    f"{stem}.js references missing #{element_id}",
                )

    def test_named_javascript_functions_have_a_reference(self):
        for name in ("admin", "access"):
            javascript = (STATIC / f"{name}.js").read_text(encoding="utf-8")
            functions = re.findall(
                r"^(?:async )?function ([A-Za-z_$][A-Za-z0-9_$]*)",
                javascript,
                re.MULTILINE,
            )

            for function in functions:
                references = re.findall(
                    rf"\b{re.escape(function)}\b",
                    javascript,
                )
                self.assertGreater(
                    len(references),
                    1,
                    f"{name}.js function {function} is never referenced",
                )

    def test_css_classes_are_referenced_or_intentionally_dynamic(self):
        dynamic_classes = {
            "state-closed",
            "state-cooling",
            "state-heating",
            "state-idle",
            "state-locked",
            "state-off",
            "state-on",
            "state-open",
            "state-opening",
            "state-playing",
            "state-unavailable",
            "state-unknown",
            "state-unlocked",
        }

        for stem in ("admin", "access"):
            markup_and_javascript = "\n".join(
                (STATIC / f"{stem}.{suffix}").read_text(encoding="utf-8")
                for suffix in ("html", "js")
            )
            css = (STATIC / f"{stem}.css").read_text(encoding="utf-8")
            classes = set(
                re.findall(r"(?<![\w-])\.([A-Za-z_][\w-]*)", css)
            )
            for class_name in classes - dynamic_classes:
                self.assertRegex(
                    markup_and_javascript,
                    rf"(?<![\w-]){re.escape(class_name)}(?![\w-])",
                    f"{stem}.css class .{class_name} is never referenced",
                )


if __name__ == "__main__":
    unittest.main()
