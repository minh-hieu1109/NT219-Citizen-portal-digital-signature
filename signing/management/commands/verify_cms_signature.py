from django.core.management.base import BaseCommand, CommandError

from signing.cms_services import verify_cms_detached_signature


class Command(BaseCommand):
    help = "Verify CMS/PKCS#7 detached signature (DER .p7s)"

    def add_arguments(self, parser):
        parser.add_argument("--input", required=True, dest="input_file")
        parser.add_argument("--signature", required=True, dest="signature")
        parser.add_argument("--ca", required=False, dest="ca")

    def handle(self, *args, **options):
        result = verify_cms_detached_signature(
            input_file=options["input_file"],
            cms_signature_path=options["signature"],
            ca_cert_path=options.get("ca"),
        )

        if not result.get("ok"):
            raise CommandError(result.get("message", "Failed to verify CMS signature."))

        mode = result.get("verification_mode", "unknown")
        self.stdout.write(self.style.SUCCESS(f"CMS signature verified (mode={mode})."))
        if result.get("warning"):
            self.stdout.write(self.style.WARNING(result["warning"]))
