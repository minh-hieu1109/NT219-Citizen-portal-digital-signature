from pathlib import Path
from dotenv import load_dotenv
import os

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')

SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = os.getenv('DEBUG', 'False') == 'True'

PKI_OPENSSL_BIN = "/usr/bin/openssl"
PKI_ROOT_CA_CERT = BASE_DIR / "pki-lab" / "certs" / "rootCA.crt"
PKI_ROOT_CA_KEY = BASE_DIR / "pki-lab" / "private" / "rootCA.key"
PKI_OPENSSL_CNF = BASE_DIR / "pki-lab" / "openssl.cnf"

PKI_USER_PRIVATE_DIR = BASE_DIR / "pki-lab" / "users" / "private"
PKI_USER_CERT_DIR = BASE_DIR / "pki-lab" / "certs" / "users"
PKI_USER_CSR_DIR = BASE_DIR / "pki-lab" / "csr" / "users"
PKI_OPENSSL_CA_CNF = BASE_DIR / "pki-lab" / "openssl_ca.cnf"
PKI_CRL_DIR = BASE_DIR / "pki-lab" / "crl"
PKCS11_LIB_PATH = "/usr/lib/softhsm/libsofthsm2.so"
PKCS11_TOKEN_LABEL = "citizen-portal-token"
PKCS11_TOKEN_PIN = "123456"
PKCS11_TOKEN_SO_PIN = "12345678"
PKCS11_KEY_LABEL_PREFIX = "user-key"

PKI_TSA_CONF = BASE_DIR / "pki-lab" / "tsa" / "tsa.conf"
PKI_TSA_SECTION = "tsa_config1"
PKI_TSA_CERT = BASE_DIR / "pki-lab" / "tsa" / "certs" / "tsa.crt"

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'rest_framework',
    
    'documents',
    'signing',
    'verification',
    'audit',
    "accounts.apps.AccountsConfig",
    "frontend.apps.FrontendConfig",
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'


# Database
# https://docs.djangoproject.com/en/6.0/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME", "citizen_db"),
        "USER": os.getenv("DB_USER", "citizen_user"),
        "PASSWORD": os.getenv("DB_PASSWORD", "12345678"),
        "HOST": os.getenv("DB_HOST", "db"),
        "PORT": os.getenv("DB_PORT", "5432"),
    }
}


# Password validation
# https://docs.djangoproject.com/en/6.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/6.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/6.0/howto/static-files/

STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
AUTH_USER_MODEL = 'accounts.User'

LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.BasicAuthentication",
    ],
}
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

ALLOWED_HOSTS = ["127.0.0.1", "localhost", "web"]

REMOTE_SIGNING_REQUEST_TTL_MINUTES = int(
    os.getenv("REMOTE_SIGNING_REQUEST_TTL_MINUTES", "10")
)
REQUIRE_STRONG_AUTH_FOR_REMOTE_SIGNING = os.getenv(
    "REQUIRE_STRONG_AUTH_FOR_REMOTE_SIGNING",
    "False",
) == "True"

ENABLE_OCSP_CHECK = os.getenv("ENABLE_OCSP_CHECK", "True") == "True"
OCSP_RESPONDER_URL = os.getenv("OCSP_RESPONDER_URL", "http://localhost:8888")
OPENSSL_BIN = os.getenv("OPENSSL_BIN", "openssl")

SITE_BASE_URL = "http://127.0.0.1:8010/"