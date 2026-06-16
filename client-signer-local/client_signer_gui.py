import base64
import hashlib
import json
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urljoin

import requests
import tkinter as tk
from tkinter import messagebox

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


SERVER_URL = "http://127.0.0.1:8010"
BASE_DIR = Path(__file__).resolve().parent
PRIVATE_KEY = BASE_DIR / "client_keys" / "citizen_mldsa.key"

OPENSSL = "openssl"


# Ephemeral device keypair.
# Key này KHÔNG PHẢI private key ML-DSA ký tài liệu.
# Nó chỉ dùng để chứng minh request sau khi pair đúng là từ local signer này.
device_private_key = ed25519.Ed25519PrivateKey.generate()
device_public_key = device_private_key.public_key()

device_public_key_pem = device_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")


class ClientSignerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Citizen ML-DSA Local Signer")

        self.requests = []
        self.current_request = None

        # Token này không nhập từ UI.
        # Nó được server trả về sau khi nhập đúng pairing code.
        self.client_token = ""

        pairing_frame = tk.Frame(root)
        pairing_frame.pack(padx=10, pady=5, fill=tk.X)

        tk.Label(pairing_frame, text="Pairing code:").pack(side=tk.LEFT)

        self.pairing_code_var = tk.StringVar()
        tk.Entry(
            pairing_frame,
            textvariable=self.pairing_code_var,
            width=30,
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            pairing_frame,
            text="Pair device",
            command=self.pair_device,
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            pairing_frame,
            text="Refresh request",
            command=self.refresh,
        ).pack(side=tk.LEFT, padx=5)

        self.status_var = tk.StringVar()
        self.status_var.set("Enter pairing code from portal, then click Pair device.")

        tk.Label(
            root,
            textvariable=self.status_var,
            anchor="w",
            fg="blue",
        ).pack(padx=10, pady=5, fill=tk.X)

        self.listbox = tk.Listbox(root, width=120, height=15)
        self.listbox.pack(padx=10, pady=10)

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)

        tk.Button(
            btn_frame,
            text="Sign selected document",
            command=self.sign_selected,
        ).pack(side=tk.LEFT, padx=5)

    def signed_device_headers(self, method, path, body_bytes=b""):
        """
        Tạo headers chứng minh request này đến từ đúng local signer đã pair.

        Server sẽ verify:
        - X-Client-Signing-Session
        - X-Device-Timestamp
        - X-Device-Body-SHA256
        - X-Device-Signature
        """
        if not self.client_token:
            raise RuntimeError("Device is not paired yet. Missing client_token.")

        timestamp = str(int(time.time()))
        body_hash = hashlib.sha256(body_bytes or b"").hexdigest()

        message = "\n".join([
            method.upper(),
            path,
            timestamp,
            body_hash,
        ]).encode("utf-8")

        signature = device_private_key.sign(message)

        return {
            "X-Client-Signing-Session": self.client_token,
            "X-Device-Timestamp": timestamp,
            "X-Device-Body-SHA256": body_hash,
            "X-Device-Signature": base64.b64encode(signature).decode("utf-8"),
        }

    def pair_device(self):
        pairing_code = self.pairing_code_var.get().strip()

        if not pairing_code:
            messagebox.showwarning(
                "Missing pairing code",
                "Please enter the pairing code shown in the portal.",
            )
            return

        url = f"{SERVER_URL}/api/signing/api/client/pair/"

        try:
            resp = requests.post(
                url,
                json={
                    "pairing_code": pairing_code,
                    "device_name": "Local ML-DSA Signer",
                    "device_public_key_pem": device_public_key_pem,
                },
                timeout=20,
            )
        except Exception as e:
            messagebox.showerror("Connection error", str(e))
            return

        try:
            data = resp.json()
        except Exception:
            messagebox.showerror(
                "Server returned non-JSON response",
                f"URL: {url}\n"
                f"Status: {resp.status_code}\n"
                f"Content-Type: {resp.headers.get('Content-Type')}\n\n"
                f"{resp.text[:3000]}",
            )
            return

        if resp.status_code != 200 or not data.get("ok"):
            messagebox.showerror("Pair failed", data.get("error", str(data)))
            return

        self.client_token = data["client_token"]

        self.status_var.set(
            f"Device paired for request #{data.get('request_id')} - "
            f"{data.get('document_title')}. Waiting for portal confirmation."
        )

        self.listbox.delete(0, tk.END)
        self.listbox.insert(
            tk.END,
            "Device paired successfully. Please confirm this signing session in the portal, then click Refresh request.",
        )

        messagebox.showinfo(
            "Device paired",
            "Device paired successfully.\n\n"
            "Now go back to the portal and click Confirm signing session.\n"
            "After confirmation, click Refresh request in this app.",
        )

    def refresh(self):
        if not self.client_token:
            messagebox.showwarning(
                "Device not paired",
                "Please enter the pairing code and click Pair device first.",
            )
            return

        self.listbox.delete(0, tk.END)
        self.requests = []
        self.current_request = None

        path = "/api/signing/api/client/pending/"
        url = f"{SERVER_URL}{path}"

        try:
            headers = self.signed_device_headers("GET", path, b"")

            resp = requests.get(
                url,
                headers=headers,
                timeout=20,
            )
        except Exception as e:
            messagebox.showerror("Connection error", str(e))
            return

        try:
            data = resp.json()
        except Exception:
            messagebox.showerror(
                "Server returned non-JSON response",
                f"URL: {url}\n"
                f"Status: {resp.status_code}\n"
                f"Content-Type: {resp.headers.get('Content-Type')}\n\n"
                f"{resp.text[:3000]}",
            )
            return

        if resp.status_code != 200 or not data.get("ok"):
            messagebox.showerror("Error", data.get("error", str(data)))
            return

        if data.get("status") == "waiting_portal_confirmation":
            self.status_var.set("Waiting for confirmation in portal.")
            self.listbox.insert(
                tk.END,
                data.get(
                    "message",
                    "Device paired. Waiting for signer confirmation in portal.",
                ),
            )
            messagebox.showinfo(
                "Waiting for confirmation",
                data.get(
                    "message",
                    "Please confirm this signing session in the portal.",
                ),
            )
            return

        request_item = data.get("request")
        self.requests = [request_item] if request_item else []

        if not self.requests:
            self.status_var.set("No pending request.")
            self.listbox.insert(tk.END, "No pending client signing requests.")
            return

        for item in self.requests:
            document_digest = item.get("document_digest") or item.get("document_hash") or ""
            field_name = item.get("field_name", "")

            line = (
                f"Request #{item['request_id']} | "
                f"Document #{item['document_id']} | "
                f"{item['document_title']} | "
                f"Algorithm: {item['algorithm']} | "
                f"Field: {field_name} | "
                f"Digest: {document_digest[:16]}..."
            )
            self.listbox.insert(tk.END, line)

        self.status_var.set("Request ready. Select the document and click Sign selected document.")

    def sign_selected(self):
        if not self.client_token:
            messagebox.showwarning(
                "Device not paired",
                "Please pair this device first using the pairing code.",
            )
            return

        idx = self.listbox.curselection()
        if not idx:
            messagebox.showwarning("Select", "Please select a document to sign.")
            return

        if not self.requests:
            messagebox.showwarning("No request", "No pending request to sign.")
            return

        item = self.requests[idx[0]]
        self.current_request = item

        if item.get("algorithm") != "ML-DSA-65":
            messagebox.showerror(
                "Unsupported algorithm",
                f"Expected ML-DSA-65, got {item.get('algorithm')}",
            )
            return

        if not PRIVATE_KEY.exists():
            messagebox.showerror("Missing key", f"Private key not found:\n{PRIVATE_KEY}")
            return

        signed_attrs_b64 = item.get("signed_attrs_b64")
        if not signed_attrs_b64:
            messagebox.showerror(
                "Missing signed_attrs_b64",
                "Server did not provide signed_attrs_b64.\n\n"
                "Make sure the signing session is confirmed in the portal.",
            )
            return

        document_digest = item.get("document_digest", "")
        field_name = item.get("field_name", "")

        confirm = messagebox.askyesno(
            "Confirm PAdES signing",
            f"You are signing server-prepared PAdES data:\n\n"
            f"Request #{item['request_id']}\n"
            f"Document: {item['document_title']}\n"
            f"Algorithm: {item['algorithm']}\n"
            f"Field: {field_name}\n"
            f"Document digest: {document_digest}\n\n"
            f"The portal prepared the PDF ByteRange and SignedAttributes.\n"
            f"This local app will sign only the SignedAttributes with the local ML-DSA private key.\n\n"
            f"Continue?",
        )

        if not confirm:
            return

        try:
            signed_attrs_bytes = base64.b64decode(signed_attrs_b64)

            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir = Path(tmpdir)
                tbs_path = tmpdir / "signed_attrs.der"
                sig_path = tmpdir / "signature.bin"

                tbs_path.write_bytes(signed_attrs_bytes)

                proc = subprocess.run(
                    [
                        OPENSSL,
                        "pkeyutl",
                        "-sign",
                        "-inkey",
                        str(PRIVATE_KEY),
                        "-rawin",
                        "-in",
                        str(tbs_path),
                        "-out",
                        str(sig_path),
                    ],
                    capture_output=True,
                    text=True,
                )

                if proc.returncode != 0:
                    messagebox.showerror(
                        "OpenSSL signing failed",
                        f"Return code: {proc.returncode}\n\n"
                        f"STDOUT:\n{proc.stdout}\n\n"
                        f"STDERR:\n{proc.stderr}",
                    )
                    return

                signature_b64 = base64.b64encode(sig_path.read_bytes()).decode("utf-8")

            submit_path = item["submit_url"]
            submit_url = urljoin(SERVER_URL, submit_path)

            body = {
                "algorithm": "ML-DSA-65",
                "signature_b64": signature_b64,
            }

            # Quan trọng:
            # Server verify X-Device-Body-SHA256 trên đúng raw body.
            # Vì vậy phải dùng data=body_bytes, không dùng json=body.
            body_bytes = json.dumps(body).encode("utf-8")

            headers = self.signed_device_headers(
                "POST",
                submit_path,
                body_bytes,
            )
            headers["Content-Type"] = "application/json"

            submit_resp = requests.post(
                submit_url,
                headers=headers,
                data=body_bytes,
                timeout=30,
            )

            try:
                result = submit_resp.json()
            except Exception:
                messagebox.showerror(
                    "Invalid JSON response",
                    f"Status: {submit_resp.status_code}\n\n{submit_resp.text[:1000]}",
                )
                return

            if submit_resp.status_code != 200 or not result.get("ok"):
                messagebox.showerror("Submit failed", result.get("error", str(result)))
                return

            messagebox.showinfo(
                "Signed",
                f"Signed successfully!\n\n"
                f"SignatureRecord #{result.get('signature_record_id')}\n"
                f"Document: {result.get('document_title', '')}",
            )

            self.requests = []
            self.current_request = None
            self.client_token = ""
            self.pairing_code_var.set("")

            self.status_var.set("Signing completed. Session has been invalidated.")
            self.listbox.delete(0, tk.END)
            self.listbox.insert(
                tk.END,
                "Signing completed. Pairing code and client session have been invalidated.",
            )

        except Exception as e:
            messagebox.showerror("Unexpected error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientSignerApp(root)
    root.mainloop()