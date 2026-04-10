import os
import django
from django.conf import settings

# === PHẦN QUAN TRỌNG: Thiết lập settings trước khi dùng ===
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')  
# Thay 'config.settings' bằng tên project + .settings của bạn
# Ví dụ: nếu project tên là 'citizen_portal' thì dùng 'citizen_portal.settings'

django.setup()   # Bắt buộc phải gọi dòng này

# Bây giờ mới dùng được settings
print(settings.PKI_ROOT_CA_CERT)
print(settings.PKI_SIGNER_CERT)
print(settings.PKI_SIGNER_KEY)

print(settings.PKI_ROOT_CA_CERT.exists())
print(settings.PKI_SIGNER_CERT.exists())
print(settings.PKI_SIGNER_KEY.exists())