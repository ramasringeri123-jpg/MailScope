from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


BASE_DIR = Path(__file__).resolve().parent
KEY_FILE = BASE_DIR / "server.key"
CERT_FILE = BASE_DIR / "server.crt"


print("Generating MailScope laboratory certificate...")


# Generate a private RSA key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


# Certificate identity
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MailScope Laboratory"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])


# Build the certificate
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(
                __import__("ipaddress").ip_address("127.0.0.1")
            ),
        ]),
        critical=False,
    )
    .sign(private_key, hashes.SHA256())
)


# Save private key
with open(KEY_FILE, "wb") as file:
    file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


# Save certificate
with open(CERT_FILE, "wb") as file:
    file.write(
        certificate.public_bytes(serialization.Encoding.PEM)
    )


print()
print("Certificate generated successfully.")
print()
print(f"Certificate: {CERT_FILE}")
print(f"Private key: {KEY_FILE}")
print()
print("MailScope laboratory TLS identity is ready.")