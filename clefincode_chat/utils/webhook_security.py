"""Only Meta can deliver messages to the WhatsApp, Instagram and Messenger webhooks.

Before this change the three webhooks (webhook.handle, instagram_handle, messenger_handle) accepted any
POST, so anyone on the internet could insert a fake incoming message ("from" any number or Instagram
user) into the chat inbox. Meta signs every delivery with the app's secret in the X-Hub-Signature-256
header (HMAC-SHA256 of the raw body); this module checks it.

Each integration (ClefinCode WhatsApp / Instagram / Facebook Messenger Integration) has a "Meta App
Secret" field (Meta for Developers > App settings > Basic > App secret). Without it, deliveries are
refused and an Error Log says why: a webhook that cannot tell Meta from anyone else must not accept
messages.

The GET verification also refused nothing when no verify token was set (None == None); it now needs one.
"""

import hashlib
import hmac

import frappe
from frappe.utils.password import get_decrypted_password
from werkzeug.wrappers import Response


def meta_signature_ok(integration):
	"""True if this request carries a valid Meta signature for the integration's App Secret."""
	secret = get_decrypted_password(integration, integration, "app_secret", raise_exception=False)
	if not secret:
		frappe.log_error(title=f"{integration}: delivery refused",
			message="No Meta App Secret is set, so the sender cannot be checked. Set it in the integration settings.")
		return False
	given = frappe.request.headers.get("X-Hub-Signature-256") or ""
	if not given.startswith("sha256="):
		return False
	expected = hmac.new(secret.encode(), frappe.request.get_data() or b"", hashlib.sha256).hexdigest()
	return hmac.compare_digest(given[len("sha256="):], expected)


def verify_token_ok(integration):
	expected = frappe.db.get_single_value(integration, "webhook_verify_token")
	return bool(expected) and hmac.compare_digest(str(frappe.form_dict.get("hub.verify_token") or ""), str(expected))


def refused():
	return Response("Forbidden", status=403)
