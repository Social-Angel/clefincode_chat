"""Push notifications can only be sent by the server's own code, never by a web request.

Run: bench --site <site> run-tests --module clefincode_chat.tests.test_push_not_public
"""
import frappe
from frappe.tests import IntegrationTestCase

from clefincode_chat.utils import fcm_notifications as f


class TestPushNotPublic(IntegrationTestCase):
	def test_push_senders_are_not_web_methods(self):
		for fn in (f.send_notification_via_firebase, f.send_notification_log_via_firebase):
			self.assertNotIn(fn, frappe.whitelisted)
			self.assertNotIn(fn, frappe.guest_methods)
