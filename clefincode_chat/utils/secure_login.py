"""Safe sign-in for the chat app's login endpoints.

Every versioned login endpoint (api_1_0_1 ... api_1_3_4) is open to anyone on the internet, and before
this change it:

* told the caller whether an account exists and whether it is disabled, so anyone could find out
  which email addresses have accounts;
* checked the password itself, skipping Frappe's protections: the failed-attempt lockout per user
  and per IP, "Restrict IP", "Login after / before" hours, and two-factor authentication;
* on every successful login replaced the user's API secret, which silently broke any other tool
  signed in with that key, and handed back a permanent key pair.

Now every version goes through this module:

* one answer for every failure ("Incorrect email or password");
* the password is checked by Frappe's own LoginManager.authenticate, so failures are counted and
  lock out exactly as on the web login page, then validate_ip_address and validate_hour;
* refused when two-factor authentication applies to the user (a key pair would bypass it);
* each endpoint is rate limited per IP (ATTEMPTS per WINDOW seconds);
* the key-based versions reuse the user's existing API secret instead of replacing it, and create a
  pair only when the user has none.
"""

import frappe
from frappe.auth import LoginManager, validate_ip_address
from frappe.twofactor import should_run_2fa
from frappe.utils.password import get_decrypted_password

FAILED = "Incorrect email or password"
ATTEMPTS = 5
WINDOW = 5 * 60


def failure():
	return [{"status": 0, "description": FAILED, "data": None}]


def authenticate(email, password):
	"""The user's name if this email and password may sign in, else None. Never says why."""
	if not email or not password:
		return None
	name = frappe.db.get_value("User", {"email": email}, "name")
	if not name or name == "Guest":
		return None
	# A LoginManager without __init__: __init__ starts or resumes a session, which only the
	# session-based version (api_1_3_4) wants, and only after the password is right.
	lm = LoginManager.__new__(LoginManager)
	lm.user = None
	try:
		lm.authenticate(user=name, pwd=password)
		if should_run_2fa(lm.user):
			return None
		validate_ip_address(lm.user)
		lm.validate_hour()
	except Exception:
		# AuthenticationError and friends: the reason is in the Authentication Log, not in the reply.
		return None
	return lm.user


def api_keys(name):
	"""(api_key, api_secret, full_name) for the key-based versions. Reuses the existing secret."""
	user = frappe.get_doc("User", name)
	secret = get_decrypted_password("User", name, "api_secret", raise_exception=False) if user.api_key else None
	if not secret:
		secret = frappe.generate_hash(length=15)
		if not user.api_key:
			user.api_key = frappe.generate_hash(length=15)
		user.api_secret = secret
		user.save(ignore_permissions=True)
	return user.api_key, secret, user.full_name
