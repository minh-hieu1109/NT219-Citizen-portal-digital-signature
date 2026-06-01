from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.test import Client


class Command(BaseCommand):
    help = "Run lightweight smoke checks for web demo routes."

    def handle(self, *args, **options):
        call_command("create_demo_users")

        client = Client()
        ok = True

        login_ok = client.login(username="admin@example.com", password="Admin@123456")
        if not login_ok:
            self.stdout.write("[FAIL] login admin@example.com")
            raise SystemExit(1)

        routes = [
            "/",
            "/documents/",
            "/documents/upload/",
            "/signing/requests/",
            "/signing/requests/create/",
            "/verification/results/",
            "/ra/pending/",
            "/audit/",
        ]

        for route in routes:
            response = client.get(route, HTTP_HOST="localhost")
            if response.status_code == 200:
                self.stdout.write(f"[OK] {route}")
            else:
                self.stdout.write(f"[FAIL] {route} status={response.status_code}")
                ok = False

        if not ok:
            raise SystemExit(1)
