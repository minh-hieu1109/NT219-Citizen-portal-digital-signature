import base64
import subprocess
import tempfile
import hashlib
from pathlib import Path
from urllib.parse import urljoin

import requests
import tkinter as tk
from tkinter import messagebox


SERVER_URL = "http://127.0.0.1:8010"
BASE_DIR = Path(__file__).resolve().parent
PRIVATE_KEY = BASE_DIR / "client_keys" / "citizen_mldsa.key"

OPENSSL = "openssl"


class ClientSignerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Citizen ML-DSA Client Signer")
        self.requests = []
        token_frame = tk.Frame(root)
        token_frame.pack(padx=10, pady=5, fill=tk.X)

        tk.Label(token_frame, text="Signing session token:").pack(side=tk.LEFT)
        self.token_var = tk.StringVar()
        tk.Entry(token_frame, textvariable=self.token_var, width=90, show="*").pack(side=tk.LEFT, padx=5)
        self.listbox = tk.Listbox(root, width=110, height=15)
        self.listbox.pack(padx=10, pady=10)

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="Refresh pending document", command=self.refresh).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Sign selected document", command=self.sign_selected).pack(side=tk.LEFT, padx=5)

    def headers(self):
        token = self.token_var.get().strip()
        return {
            "X-Client-Signing-Session": token
        }

    def refresh(self):
        if not self.token_var.get().strip():
            messagebox.showwarning("Missing token", "Please paste the signing session token.")
            return

        self.listbox.delete(0, tk.END)
        self.requests = []

        url = f"{SERVER_URL}/api/signing/api/client/pending/"

        try:
            resp = requests.get(url, headers=self.headers(), timeout=20)
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
                f"{resp.text[:3000]}"
            )
            return

        if resp.status_code != 200 or not data.get("ok"):
            messagebox.showerror("Error", data.get("error", str(data)))
            return

        request_item = data.get("request")
        self.requests = [request_item] if request_item else []

        if not self.requests:
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

    def sign_selected(self):
        if not self.token_var.get().strip():
            messagebox.showwarning("Missing token", "Please paste the signing session token.")
            return

        idx = self.listbox.curselection()
        if not idx:
            messagebox.showwarning("Select", "Please select a document to sign.")
            return

        if not self.requests:
            messagebox.showwarning("No request", "No pending request to sign.")
            return

        item = self.requests[idx[0]]

        if item.get("algorithm") != "ML-DSA-65":
            messagebox.showerror(
                "Unsupported algorithm",
                f"Expected ML-DSA-65, got {item.get('algorithm')}"
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
                "This means the server-side PAdES external signing session has not been updated yet."
            )
            return

        submit_url = urljoin(SERVER_URL, item["submit_url"])

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
            f"The server prepared the PDF ByteRange and SignedAttributes.\n"
            f"This client will sign only the SignedAttributes with the local ML-DSA key.\n\n"
            f"Continue?"
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
                        f"STDERR:\n{proc.stderr}"
                    )
                    return

                signature_b64 = base64.b64encode(sig_path.read_bytes()).decode("utf-8")

            submit_resp = requests.post(
                submit_url,
                headers={**self.headers(), "Content-Type": "application/json"},
                json={
                    "algorithm": "ML-DSA-65",
                    "signature_b64": signature_b64,
                },
                timeout=20,
            )

            try:
                result = submit_resp.json()
            except Exception:
                messagebox.showerror(
                    "Invalid JSON response",
                    f"Status: {submit_resp.status_code}\n\n{submit_resp.text[:1000]}"
                )
                return

            if submit_resp.status_code != 200 or not result.get("ok"):
                messagebox.showerror("Submit failed", str(result))
                return

            messagebox.showinfo(
                "Signed",
                f"Signed successfully!\n\n"
                f"SignatureRecord #{result['signature_record_id']}\n"
                f"Algorithm: {result['algorithm']}"
            )

            self.requests = []
            self.listbox.delete(0, tk.END)
            self.listbox.insert(
                tk.END,
                "Signing completed. This session token has been used and invalidated."
            )

        except Exception as e:
            messagebox.showerror("Unexpected error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientSignerApp(root)
    root.mainloop()