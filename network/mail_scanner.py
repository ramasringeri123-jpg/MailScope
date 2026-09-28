import socket
import ssl
import smtplib


class MailScanner:
    """
    MailScope SMTP + TLS security scanner.
    """

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def scan(self):
        result = {
            "host": self.host,
            "port": self.port,
            "protocol": None,
            "connected": False,
            "starttls": False,
            "tls": False,
            "tls_version": None,
            "cipher": None,
            "certificate_subject": None,
            "certificate_issuer": None,
            "error": None,
        }

        try:
            with smtplib.SMTP(
                self.host,
                self.port,
                timeout=5
            ) as server:

                result["connected"] = True

                server.ehlo()
                result["protocol"] = "SMTP"

                result["starttls"] = server.has_extn("starttls")

                if not result["starttls"]:
                    return result

                # Perform the STARTTLS handshake.
                server.starttls()

                result["tls"] = True

                # Access the underlying TLS socket.
                tls_socket = server.sock

                if isinstance(tls_socket, ssl.SSLSocket):
                    result["tls_version"] = tls_socket.version()
                    result["cipher"] = tls_socket.cipher()

                    certificate = tls_socket.getpeercert()

                    if certificate:
                        subject = certificate.get("subject", ())
                        issuer = certificate.get("issuer", ())

                        result["certificate_subject"] = subject
                        result["certificate_issuer"] = issuer

        except (socket.timeout, ConnectionRefusedError) as error:
            result["error"] = str(error)

        except Exception as error:
            result["error"] = str(error)

        return result


if __name__ == "__main__":

    scanner = MailScanner(
        host="127.0.0.1",
        port=2525
    )

    result = scanner.scan()

    print()
    print("========== MAILSCOPE TLS SCAN ==========")

    print(f"Host               : {result['host']}")
    print(f"Port               : {result['port']}")
    print(f"Connected          : {result['connected']}")
    print(f"Protocol           : {result['protocol']}")
    print(f"STARTTLS           : {result['starttls']}")
    print(f"TLS Handshake      : {result['tls']}")
    print(f"TLS Version        : {result['tls_version']}")
    print(f"Cipher              : {result['cipher']}")
    print(f"Certificate Subject: {result['certificate_subject']}")
    print(f"Certificate Issuer : {result['certificate_issuer']}")

    print(f"Error              : {result['error']}")

    print("========================================")