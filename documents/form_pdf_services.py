from pathlib import Path

import qrcode
from django.conf import settings
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def generate_citizen_form_pdf(document, citizen, form_data):
    output_dir = Path(settings.MEDIA_ROOT) / "documents" / "generated_forms"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / f"document_{document.id}_form.pdf"

    verify_url = (
        f"{settings.SITE_BASE_URL}"
        f"/public/verify/document/{document.verification_id}/"
    )

    qr_path = output_dir / f"document_{document.id}_qr.png"
    qr = qrcode.make(verify_url)
    qr.save(qr_path)

    c = canvas.Canvas(str(output_path), pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 60, "CITIZEN PORTAL DIGITAL FORM")

    c.setFont("Helvetica", 11)
    c.drawString(50, height - 100, f"Citizen: {citizen.full_name or citizen.email}")
    c.drawString(50, height - 120, f"Email: {citizen.email}")
    c.drawString(50, height - 140, f"Citizen ID: {getattr(citizen, 'citizen_id', '')}")

    c.drawString(50, height - 180, f"Title: {form_data.get('title', '')}")
    c.drawString(50, height - 210, "Content:")

    text = c.beginText(50, height - 235)
    text.setFont("Helvetica", 10)

    content = form_data.get("content", "")
    for line in content.splitlines():
        text.textLine(line[:100])

    c.drawText(text)

    # Vùng hiển thị chữ ký
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, 180, "Citizen Signature")
    c.rect(50, 80, 220, 80)

    c.drawString(330, 180, "Officer Approval Signature")
    c.rect(330, 80, 220, 80)

    # QR verify
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, 45, "Scan QR to verify this document:")
    c.drawImage(str(qr_path), 210, 25, width=70, height=70)

    c.setFont("Helvetica", 8)
    c.drawString(290, 55, verify_url[:90])

    c.showPage()
    c.save()

    return output_path