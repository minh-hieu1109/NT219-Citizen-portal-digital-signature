from django.core.management.base import BaseCommand, CommandError

from signing.cms_services import create_cms_detached_signature


class Command(BaseCommand):
    help = "Create CMS/PKCS#7 detached signature (DER .p7s)"

    def add_arguments(self, parser):
        parser.add_argument("--input", required=True, dest="input_file")
        parser.add_argument("--cert", required=True, dest="cert")
        parser.add_argument("--key", required=True, dest="key")
        parser.add_argument("--out", required=True, dest="out")
        parser.add_argument("--ca", required=False, dest="ca")

    def handle(self, *args, **options):
        result = create_cms_detached_signature(
            input_file=options["input_file"],
            signer_cert_path=options["cert"],
            signer_key_path=options["key"],
            ca_cert_path=options.get("ca"),
            output_path=options["out"],
        )

        if not result.get("ok"):
            raise CommandError(result.get("message", "Failed to create CMS signature."))

        self.stdout.write(self.style.SUCCESS(f"CMS signature created: {result['signature_path']}"))
