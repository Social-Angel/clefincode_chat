"""Login, webhook signature and every-save hook fixes.

Run: bench --site <site> run-tests --module clefincode_chat.utils.test_security_fixes
The per-IP rate limit only applies to real HTTP requests; check it against a running site.
"""

import hashlib
import hmac
import json
from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils.password import update_password

from clefincode_chat.api.api_1_3_1 import api as api_1_3_1
from clefincode_chat.utils import secure_login, webhook_security
from clefincode_chat.utils import whatsapp_notification as wn

PASSWORD = "Zz-Test-pass-91!"


def make_user(enabled=1):
	email = f"zz-chat-{frappe.generate_hash(length=8)}@example.com"
	user = frappe.get_doc({"doctype": "User", "email": email, "first_name": "Zz Chat", "enabled": enabled,
		"send_welcome_email": 0, "user_type": "System User"}).insert(ignore_permissions=True)
	update_password(user.name, PASSWORD)
	return user.name


class TestLogin(IntegrationTestCase):
	def setUp(self):
		# Frappe counts failed attempts per IP as well as per user; a real request always has an IP.
		frappe.local.request_ip = "127.0.0.1"

	def test_every_failure_gives_the_same_answer(self):
		disabled = make_user(enabled=0)
		real = make_user()
		answers = {
			json.dumps(api_1_3_1.login("nobody-zz@example.com", PASSWORD)),
			json.dumps(api_1_3_1.login(disabled, PASSWORD)),
			json.dumps(api_1_3_1.login(real, "wrong-password")),
		}
		self.assertEqual(answers, {json.dumps(secure_login.failure())})

	def test_right_password_returns_keys_and_a_second_login_keeps_the_secret(self):
		user = make_user()
		first = api_1_3_1.login(user, PASSWORD)[0]
		self.assertEqual(first["status"], 1)
		second = api_1_3_1.login(user, PASSWORD)[0]
		self.assertEqual(first["data"][0]["api_secret"], second["data"][0]["api_secret"])
		self.assertEqual(first["data"][0]["api_key"], second["data"][0]["api_key"])

	def test_an_existing_api_secret_is_reused_not_replaced(self):
		user = make_user()
		doc = frappe.get_doc("User", user)
		doc.api_key, doc.api_secret = "zzkey" + frappe.generate_hash(length=8), "zzsecret12345"
		doc.save(ignore_permissions=True)
		got = api_1_3_1.login(user, PASSWORD)[0]["data"][0]
		self.assertEqual(got["api_secret"], "zzsecret12345")

	def test_two_factor_users_cannot_get_a_key(self):
		user = make_user()
		with patch.object(secure_login, "should_run_2fa", return_value=True):
			self.assertEqual(api_1_3_1.login(user, PASSWORD), secure_login.failure())

	def test_the_password_is_checked_by_frappes_login(self):
		# LoginManager.authenticate is what counts failures and locks accounts out, as on the web login.
		from frappe.auth import LoginManager
		user = make_user()
		with patch.object(LoginManager, "authenticate", autospec=True, wraps=LoginManager.authenticate) as auth:
			api_1_3_1.login(user, "wrong-password")
		auth.assert_called_once()


class FakeRequest:
	def __init__(self, body, signature=None):
		self._body = body
		self.headers = {"X-Hub-Signature-256": signature} if signature else {}

	def get_data(self):
		return self._body


class TestWebhookSignature(IntegrationTestCase):
	INTEGRATION = "ClefinCode Instagram Integration"

	def check(self, body, signature, secret="zz-app-secret"):
		with patch.object(webhook_security, "get_decrypted_password", return_value=secret), \
				patch.object(frappe, "request", FakeRequest(body, signature), create=True):
			return webhook_security.meta_signature_ok(self.INTEGRATION)

	def sign(self, body, secret="zz-app-secret"):
		return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

	def test_a_delivery_signed_by_meta_is_accepted(self):
		body = b'{"entry": []}'
		self.assertTrue(self.check(body, self.sign(body)))

	def test_unsigned_wrongly_signed_or_altered_deliveries_are_refused(self):
		body = b'{"entry": []}'
		self.assertFalse(self.check(body, None))
		self.assertFalse(self.check(body, self.sign(body, "someone-else")))
		self.assertFalse(self.check(b'{"entry": [1]}', self.sign(body)))

	def test_no_app_secret_refuses_everything(self):
		body = b'{"entry": []}'
		self.assertFalse(self.check(body, self.sign(body), secret=None))

	def test_the_verify_handshake_needs_a_token_to_be_set(self):
		with patch.object(frappe.db, "get_single_value", return_value=None):
			frappe.form_dict["hub.verify_token"] = None
			self.assertFalse(webhook_security.verify_token_ok(self.INTEGRATION))
		with patch.object(frappe.db, "get_single_value", return_value="tok"):
			frappe.form_dict["hub.verify_token"] = "tok"
			self.assertTrue(webhook_security.verify_token_ok(self.INTEGRATION))
		frappe.form_dict.pop("hub.verify_token", None)


class TestEverySaveHooks(IntegrationTestCase):
	def test_a_save_with_no_chat_notifications_does_no_work(self):
		frappe.cache().set_value(wn._NOTIFICATIONS_MAP_KEY, {})  # what get_notifications_map caches on a site with none
		doc = frappe._dict(doctype="ToDo", name="x", docstatus=0, is_new=lambda: False)
		with patch.object(wn, "get_notifications_map", return_value={}) as build, \
				patch.object(wn, "_ensure_patch") as patch_db, \
				patch.object(frappe, "get_doc") as load:
			for event in ("validate", "on_update", "on_change", "after_insert"):
				wn.run_server_script_for_doc_event(doc, event)
			wn.capture_old_snapshot(doc)
		build.assert_not_called()  # read from the cache, not one query per event
		patch_db.assert_not_called()
		load.assert_not_called()

	def test_the_map_is_rebuilt_when_a_notification_changes(self):
		frappe.cache().set_value(wn._NOTIFICATIONS_MAP_KEY, {"ToDo": {"Save": ["n1"]}})
		self.assertIn("ToDo", wn._cached_notifications_map())
		wn.clear_notifications_map()
		with patch.object(wn, "get_notifications_map", return_value={}):
			self.assertEqual(wn._cached_notifications_map(), {})
