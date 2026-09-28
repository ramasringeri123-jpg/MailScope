from network.mail_scanner import MailScanner
from network.certificate_analyzer import CertificateAnalyzer
from core.security_engine import SecurityEngine


def main():

    print()
    print("=" * 60)
    print("                 MAILSCOPE")
    print("          EMAIL SECURITY ANALYZER")
    print("=" * 60)

    # ---------------------------------
    # 1. SMTP / TLS scan
    # ---------------------------------

    print()
    print("[1/3] Scanning SMTP/TLS connection...")

    scanner = MailScanner(
        host="127.0.0.1",
        port=2525
    )

    scan_result = scanner.scan()

    print("      Connection :", scan_result["connected"])
    print("      Protocol   :", scan_result["protocol"])
    print("      STARTTLS   :", scan_result["starttls"])
    print("      TLS        :", scan_result["tls"])
    print("      Version    :", scan_result["tls_version"])
    print("      Cipher     :", scan_result["cipher"])

    # ---------------------------------
    # 2. Certificate analysis
    # ---------------------------------

    print()
    print("[2/3] Analyzing certificate...")

    certificate_analyzer = CertificateAnalyzer(
        "data/lab/server.crt"
    )

    certificate_result = certificate_analyzer.analyze()

    if certificate_result["success"]:

        print("      Subject    :", certificate_result["subject"])
        print("      Issuer     :", certificate_result["issuer"])
        print("      Validity   :", certificate_result["validity"])
        print("      Key        :", certificate_result["key_type"])
        print("      Key Size   :", certificate_result["key_size"])
        print("      Self-Signed:",
              certificate_result["self_signed"])

    else:

        print("      Certificate analysis failed:")
        print("      ", certificate_result["error"])

    # ---------------------------------
    # 3. Security analysis
    # ---------------------------------

    print()
    print("[3/3] Running security assessment...")

    engine = SecurityEngine()

    security_result = engine.analyze(
        scan_result,
        certificate_result
    )

    # ---------------------------------
    # Final report
    # ---------------------------------

    print()
    print("=" * 60)
    print("                 SECURITY REPORT")
    print("=" * 60)

    print()
    print(f"Risk Level : {security_result['risk']}")
    print(f"Risk Score : {security_result['score']}/100")

    print()
    print("FINDINGS")
    print("-" * 60)

    for finding in security_result["findings"]:

        severity = finding["severity"]
        title = finding["title"]
        description = finding["description"]

        print()
        print(f"[{severity}] {title}")
        print(f"    {description}")

    print()
    print("=" * 60)
    print("              MAILSCOPE SCAN COMPLETE")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()