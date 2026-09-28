from detection.threat_detector import ThreatDetector
from network.mail_scanner import MailScanner
from network.certificate_analyzer import CertificateAnalyzer
from core.security_engine import SecurityEngine


class ThreatAssessment:

    def __init__(self):

        self.mail_scanner = MailScanner(
            host="127.0.0.1",
            port=2525
        )

        self.certificate_analyzer = CertificateAnalyzer(
            "data/lab/server.crt"
        )

        self.content_detector = ThreatDetector()

        self.security_engine = SecurityEngine()

    def analyze_email(self, email_text, attachments=None):

        # =====================================================
        # 1. NETWORK SECURITY
        # =====================================================

        network_result = self.mail_scanner.scan()

        # =====================================================
        # 2. CERTIFICATE SECURITY
        # =====================================================

        certificate_result = self.certificate_analyzer.analyze()

        # =====================================================
        # 3. EMAIL CONTENT SECURITY
        # =====================================================

        content_result = self.content_detector.analyze(
            email_text,
            attachments or []
        )

        # =====================================================
        # 4. TRANSPORT SECURITY ASSESSMENT
        # =====================================================

        transport_result = self.security_engine.analyze(
            network_result,
            certificate_result
        )

        # =====================================================
        # 5. COMBINE RESULTS
        # =====================================================

        combined_findings = []

        # Network/certificate findings
        combined_findings.extend(
            transport_result["findings"]
        )

        # Email-content findings
        combined_findings.extend(
            content_result["findings"]
        )

        # =====================================================
        # CONTENT RISK
        # =====================================================

        content_score = content_result["risk_score"]

        # =====================================================
        # TRANSPORT RISK
        # =====================================================

        transport_score = transport_result["score"]

        # =====================================================
        # FINAL RISK
        # =====================================================

        final_score = max(
            content_score,
            transport_score
        )

        if final_score >= 70:

            final_risk = "CRITICAL"

        elif final_score >= 40:

            final_risk = "HIGH"

        elif final_score >= 20:

            final_risk = "MEDIUM"

        else:

            final_risk = "LOW"

        # =====================================================
        # COUNTERMEASURE
        # =====================================================

        if final_risk == "CRITICAL":

            action = "BLOCK"

        elif final_risk == "HIGH":

            action = "WARN"

        elif final_risk == "MEDIUM":

            action = "REVIEW"

        else:

            action = "ALLOW"

        return {

            "risk_score": final_score,

            "risk_level": final_risk,

            "recommended_action": action,

            "network": network_result,

            "certificate": certificate_result,

            "content": content_result,

            "transport": transport_result,

            "findings": combined_findings
        }


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    analyzer = ThreatAssessment()

    test_email = """
    URGENT!

    Your account will be suspended.

    Please login immediately and verify your account.

    Password: TestPassword123

    Send your wallet recovery phrase if requested.

    https://secure-login.example.com
    """

    result = analyzer.analyze_email(
        test_email
    )

    print()
    print("=" * 65)
    print("                 MAILSCOPE")
    print("              THREAT ASSESSMENT")
    print("=" * 65)

    print()
    print("FINAL RISK     :", result["risk_level"])
    print("RISK SCORE     :", result["risk_score"], "/ 100")
    print("RECOMMENDED    :", result["recommended_action"])

    print()
    print("FINDINGS")
    print("-" * 65)

    for finding in result["findings"]:

        print()
        print(
            f"[{finding['severity']}] "
            f"{finding['title']}"
        )

        print(
            "    "
            + finding["description"]
            if "description" in finding
            else
            "    "
            + finding["message"]
        )

    print()
    print("=" * 65)