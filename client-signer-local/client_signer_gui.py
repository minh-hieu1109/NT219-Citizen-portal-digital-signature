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

        self.refresh()

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
            resp = requests.get(url, headers=self.headers(), timeout=10)
            data = resp.json()
        except Exception as e:
            messagebox.showerror("Connection error", str(e))
            return

        if resp.status_code != 200 or not data.get("ok"):
            messagebox.showerror("Error", data.get("error", "Unknown error"))
            return

        request_item = data.get("request")
        self.requests = [request_item] if request_item else []

        if not self.requests:
            self.listbox.insert(tk.END, "No pending client signing requests.")
            return

        for item in self.requests:
            line = (
                f"Request #{item['request_id']} | "
                f"Document #{item['document_id']} | "
                f"{item['document_title']} | "
                f"Algorithm: {item['algorithm']} | "
                f"Hash: {item['document_hash'][:16]}..."
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
            messagebox.showerror("Unsupported algorithm", f"Expected ML-DSA-65, got {item.get('algorithm')}")
            return

        if not PRIVATE_KEY.exists():
            messagebox.showerror("Missing key", f"Private key not found:\n{PRIVATE_KEY}")
            return

        file_url = urljoin(SERVER_URL, item["file_url"])
        submit_url = urljoin(SERVER_URL, item["submit_url"])

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir = Path(tmpdir)
                doc_path = tmpdir / "document_to_sign.bin"
                sig_path = tmpdir / "signature.bin"

                file_resp = requests.get(file_url, headers=self.headers(), timeout=20)

                if file_resp.status_code != 200:
                    messagebox.showerror(
                        "Download failed",
                        f"Status: {file_resp.status_code}\n\n{file_resp.text[:1000]}"
                    )
                    return

                doc_bytes = file_resp.content
                doc_path.write_bytes(doc_bytes)

                downloaded_hash = hashlib.sha256(doc_bytes).hexdigest()
                expected_hash = item.get("document_hash")

                if downloaded_hash != expected_hash:
                    messagebox.showerror(
                        "Hash mismatch",
                        f"Downloaded file hash does not match signing request.\n\n"
                        f"Expected: {expected_hash}\n"
                        f"Got:      {downloaded_hash}"
                    )
                    return

                confirm = messagebox.askyesno(
                    "Confirm signing",
                    f"You are signing:\n\n"
                    f"Request #{item['request_id']}\n"
                    f"Document: {item['document_title']}\n"
                    f"Algorithm: {item['algorithm']}\n"
                    f"Hash: {expected_hash}\n\n"
                    f"Continue?"
                )

                if not confirm:
                    return

                proc = subprocess.run([
                    OPENSSL,
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    str(PRIVATE_KEY),
                    "-rawin",
                    "-in",
                    str(doc_path),
                    "-out",
                    str(sig_path),
                ], capture_output=True, text=True)

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