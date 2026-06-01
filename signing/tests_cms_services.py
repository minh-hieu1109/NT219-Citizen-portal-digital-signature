from pathlib import Path
from unittest.mock import patch

from django.test import TestCase

from signing.cms_services import (
    create_cms_detached_signature,
    verify_cms_detached_signature,
)


class CmsServicesTests(TestCase):
    def test_create_returns_error_when_input_missing(self):
        result = create_cms_detached_signature(
            input_file="/tmp/missing-input.txt",
            signer_cert_path="/tmp/missing-cert.crt",
            signer_key_path="/tmp/missing-key.pem",
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "error")

    @patch("signing.cms_services.subprocess.run")
    def test_create_builds_expected_command(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""

        tmp_dir = Path("/tmp")
        input_file = tmp_dir / "cms_test_input.txt"
        cert_file = tmp_dir / "cms_test_cert.crt"
        key_file = tmp_dir / "cms_test_key.pem"
        input_file.write_text("abc", encoding="utf-8")
        cert_file.write_text("cert", encoding="utf-8")
        key_file.write_text("key", encoding="utf-8")

        out_file = tmp_dir / "cms_test_signature.p7s"
        result = create_cms_detached_signature(
            input_file=str(input_file),
            signer_cert_path=str(cert_file),
            signer_key_path=str(key_file),
            output_path=str(out_file),
        )

        self.assertTrue(result["ok"])
        called_cmd = mock_run.call_args[0][0]
        self.assertIn("cms", called_cmd)
        self.assertIn("-sign", called_cmd)
        self.assertIn("-outform", called_cmd)
        self.assertIn("DER", called_cmd)

    def test_verify_returns_error_when_signature_missing(self):
        input_file = Path("/tmp/cms_verify_input.txt")
        input_file.write_text("abc", encoding="utf-8")

        result = verify_cms_detached_signature(
            input_file=str(input_file),
            cms_signature_path="/tmp/missing-signature.p7s",
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "error")
