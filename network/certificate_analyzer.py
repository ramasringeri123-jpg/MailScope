from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec


class CertificateAnalyzer:
    """
    Analyzes an X.509 certificate used by the MailScope
    laboratory SMTP server.
    """

    def __init__(self, certificate_path):
        self.certificate_path = Path(certificate_path)

    def analyze(self):
        if not self.certificate_path.exists():
            return {
                "success": False,
                "error": f"Certificate not found: {self.certificate_path}"
            }

        try:
            certificate_data = self.certificate_path.read_bytes()

            certificate = x509.load_pem_x509_certificate(
                certificate_data
            )

            public_key = certificate.public_key()

            if isinstance(public_key, rsa.RSAPublicKey):
                key_type = "RSA"
                key_size = public_key.key_size

            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_type = "EC"
                key_size = public_key.curve.key_size

            else:
                key_type = type(public_key).__name__
                key_size = None

            try:
                signature_algorithm = certificate.signature_hash_algorithm.name
            except Exception:
                signature_algorithm = "Unknown"

            try:
                san = certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )

                san_names = san.value.get_values_for_type(
                    x509.DNSName
                )

                san_ips = [
                    str(ip)
                    for ip in san.value.get_values_for_type(
                        x509.IPAddress
                    )
                ]

            except x509.ExtensionNotFound:
                san_names = []
                san_ips = []

            now = __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            )

            valid_from = certificate.not_valid_before_utc
            valid_until = certificate.not_valid_after_utc

            if now < valid_from:
                validity = "NOT_YET_VALID"

            elif now > valid_until:
                validity = "EXPIRED"

            else:
                validity = "VALID"

            is_self_signed = (
                certificate.subject == certificate.issuer
            )

            return {
                "success": True,
                "subject": certificate.subject.rfc4514_string(),
                "issuer": certificate.issuer.rfc4514_string(),
                "serial_number": str(certificate.serial_number),
                "valid_from": valid_from.isoformat(),
                "valid_until": valid_until.isoformat(),
                "validity": validity,
                "signature_algorithm": signature_algorithm,
                "key_type": key_type,
                "key_size": key_size,
                "self_signed": is_self_signed,
                "dns_names": san_names,
                "ip_addresses": san_ips,
            }

        except Exception as error:
            return {
                "success": False,
                "error": str(error)
            }


if __name__ == "__main__":

    analyzer = CertificateAnalyzer(
        "data/lab/server.crt"
    )

    result = analyzer.analyze()

    print()
    print("======= CERTIFICATE ANALYSIS =======")

    if not result["success"]:
        print("Analysis failed.")
        print("Error:", result["error"])

    else:
        print("Subject            :", result["subject"])
        print("Issuer             :", result["issuer"])
        print("Serial Number      :", result["serial_number"])
        print("Valid From         :", result["valid_from"])
        print("Valid Until        :", result["valid_until"])
        print("Validity           :", result["validity"])
        print("Signature Algorithm:", result["signature_algorithm"])
        print("Key Type           :", result["key_type"])
        print("Key Size           :", result["key_size"])
        print("Self Signed        :", result["self_signed"])
        print("DNS Names          :", result["dns_names"])
        print("IP Addresses       :", result["ip_addresses"])

    print("====================================")