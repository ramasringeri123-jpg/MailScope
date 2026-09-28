from ingestion.eml_parser import EMLParser
from detection.threat_detector import ThreatDetector


class EmailAnalyzer:

    def __init__(self):

        self.parser = EMLParser()
        self.detector = ThreatDetector()

    def analyze_file(self, file_path):

        # -----------------------------------------------------
        # STEP 1 — PARSE REAL EMAIL
        # -----------------------------------------------------

        email = self.parser.parse_file(
            file_path
        )

        # -----------------------------------------------------
        # STEP 2 — GET EMAIL CONTENT
        # -----------------------------------------------------

        body = email.get(
            "body",
            ""
        )

        attachments = [
            item["filename"]
            for item in email.get(
                "attachments",
                []
            )
        ]

        # -----------------------------------------------------
        # STEP 3 — RUN THREAT DETECTION
        # -----------------------------------------------------

        detection = self.detector.analyze(
            body,
            attachments
        )

        # -----------------------------------------------------
        # STEP 4 — COMBINE EMAIL + SECURITY RESULT
        # -----------------------------------------------------

        return {
            "email": email,
            "security": detection
        }


# =============================================================
# COMMAND LINE TEST
# =============================================================

if __name__ == "__main__":

    import sys

    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            "python -m ingestion.email_analyzer "
            "data\\lab\\test_email.eml"
        )

        raise SystemExit(1)

    analyzer = EmailAnalyzer()

    result = analyzer.analyze_file(
        sys.argv[1]
    )

    email = result["email"]
    security = result["security"]

    print()
    print("=" * 65)
    print("                 MAILSCOPE")
    print("              EMAIL ANALYSIS")
    print("=" * 65)

    print()
    print("EMAIL")
    print("-" * 65)

    print(
        "Sender      :",
        email["sender"]
    )

    print(
        "Recipient   :",
        email["recipient"]
    )

    print(
        "Subject     :",
        email["subject"]
    )

    print(
        "Attachments :",
        email["attachment_count"]
    )

    print()
    print("SECURITY")
    print("-" * 65)

    print(
        "Status      :",
        "SAFE" if security["safe"] else "THREAT DETECTED"
    )

    print(
        "Severity    :",
        security["severity"]
    )

    print(
        "Risk Score  :",
        security["risk_score"],
        "/ 100"
    )

    print()
    print("FINDINGS")
    print("-" * 65)

    if not security["findings"]:

        print(
            "No threats detected."
        )

    else:

        for finding in security["findings"]:

            print(
                f"[{finding['severity']}] "
                f"{finding['title']}"
            )

            print(
                "    "
                + finding["message"]
            )

            print()

    print("=" * 65)