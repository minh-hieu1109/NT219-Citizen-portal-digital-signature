from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase


User = get_user_model()


class WebSmokeTests(TestCase):
    def setUp(self):
        call_command("create_demo_users")
        self.admin = User.objects.get(email="admin@example.com")
        self.officer = User.objects.get(email="officer@example.com")
        self.citizen = User.objects.get(email="citizen@example.com")

    def test_login_page_returns_200(self):
        response = self.client.get("/accounts/login/")
        self.assertEqual(response.status_code, 200)

    def test_dashboard_accessible_or_redirects(self):
        response = self.client.get("/")
        self.assertIn(response.status_code, [200, 302])

    def test_demo_users_command_creates_users(self):
        self.assertTrue(User.objects.filter(email="admin@example.com").exists())
        self.assertTrue(User.objects.filter(email="officer@example.com").exists())
        self.assertTrue(User.objects.filter(email="citizen@example.com").exists())

    def test_logged_in_admin_can_access_core_pages(self):
        self.client.force_login(self.admin)
        for path in [
            "/",
            "/documents/",
            "/signing/requests/",
            "/verification/results/",
            "/ra/pending/",
            "/audit/",
        ]:
            res = self.client.get(path)
            self.assertEqual(res.status_code, 200, msg=f"failed route: {path}")

    def test_officer_can_access_ra_and_audit(self):
        self.client.force_login(self.officer)
        self.assertEqual(self.client.get("/ra/pending/").status_code, 200)
        self.assertEqual(self.client.get("/audit/").status_code, 200)

    def test_citizen_forbidden_for_ra_and_audit(self):
        self.client.force_login(self.citizen)
        self.assertEqual(self.client.get("/ra/pending/").status_code, 403)
        self.assertEqual(self.client.get("/audit/").status_code, 403)

    def test_document_list_page_returns_200_for_logged_user(self):
        self.client.force_login(self.citizen)
        response = self.client.get("/documents/")
        self.assertEqual(response.status_code, 200)

    def test_signing_request_list_page_returns_200_for_logged_user(self):
        self.client.force_login(self.citizen)
        response = self.client.get("/signing/requests/")
        self.assertEqual(response.status_code, 200)

    def test_verification_results_page_returns_200_for_logged_user(self):
        self.client.force_login(self.citizen)
        response = self.client.get("/verification/results/")
        self.assertEqual(response.status_code, 200)
