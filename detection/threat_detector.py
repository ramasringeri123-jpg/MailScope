import re
from urllib.parse import urlparse


class ThreatDetector:
    """
    MailScope email-content threat detector.

    Detects:
    - Password disclosure
    - API keys
    - Private keys
    - Cryptocurrency recovery phrases
    - Suspicious URLs
    - Phishing indicators
    - Executable attachments
    """

    PASSWORD_PATTERNS = [
        r"\bpassword\s*[:=]\s*\S+",
        r"\bpasswd\s*[:=]\s*\S+",
        r"\bpwd\s*[:=]\s*\S+",
    ]

    API_KEY_PATTERNS = [
        r"\bsk-[A-Za-z0-9_-]{20,}",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bghp_[A-Za-z0-9]{20,}",
        r"\bapi[_ -]?key\s*[:=]\s*[A-Za-z0-9_\-]{12,}",
    ]

    PRIVATE_KEY_PATTERNS = [
        r"-----BEGIN PRIVATE KEY-----",
        r"-----BEGIN RSA PRIVATE KEY-----",
        r"-----BEGIN EC PRIVATE KEY-----",
    ]

    URGENCY_WORDS = [
        "urgent",
        "immediately",
        "act now",
        "verify now",
        "account suspended",
        "account will be closed",
        "final warning",
    ]

    CREDENTIAL_WORDS = [
        "login",
        "sign in",
        "verify your account",
        "enter your password",
        "confirm your password",
        "credentials",
    ]

    CRYPTO_WORDS = [
        "seed phrase",
        "recovery phrase",
        "secret phrase",
        "wallet recovery",
        "private key",
        "mnemonic phrase",
    ]

    EXECUTABLE_EXTENSIONS = [
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".msi",
        ".vbs",
        ".js",
        ".ps1",
    ]

    def analyze(self, text, attachments=None):

        if not isinstance(text, str):
            text = str(text)

        attachments = attachments or []

        findings = []
        risk_score = 0

        normalized = text.lower()

        # =====================================================
        # PASSWORD DETECTION
        # =====================================================

        for pattern in self.PASSWORD_PATTERNS:

            if re.search(pattern, text, re.IGNORECASE):

                findings.append({
                    "type": "password",
                    "severity": "HIGH",
                    "title": "Possible password disclosure",
                    "message": (
                        "The message appears to contain a password "
                        "or password-like credential."
                    ),
                })

                risk_score += 35
                break

        # =====================================================
        # API KEY DETECTION
        # =====================================================

        for pattern in self.API_KEY_PATTERNS:

            if re.search(pattern, text):

                findings.append({
                    "type": "api_key",
                    "severity": "CRITICAL",
                    "title": "Possible API key detected",
                    "message": (
                        "The message appears to contain a credential "
                        "that may provide access to an external service."
                    ),
                })

                risk_score += 50
                break

        # =====================================================
        # PRIVATE KEY DETECTION
        # =====================================================

        for pattern in self.PRIVATE_KEY_PATTERNS:

            if re.search(pattern, text, re.IGNORECASE):

                findings.append({
                    "type": "private_key",
                    "severity": "CRITICAL",
                    "title": "Private cryptographic key detected",
                    "message": (
                        "A private-key block was detected in the message."
                    ),
                })

                risk_score += 70
                break

        # =====================================================
        # CRYPTO / RECOVERY PHRASE DETECTION
        # =====================================================

        crypto_matches = []

        for word in self.CRYPTO_WORDS:

            if word in normalized:
                crypto_matches.append(word)

        # We deliberately detect the presence of crypto-secret
        # terminology rather than attempting to validate or store
        # real wallet credentials.

        if crypto_matches:

            findings.append({
                "type": "crypto_secret",
                "severity": "CRITICAL",
                "title": "Possible cryptocurrency secret",
                "message": (
                    "The message contains terminology associated "
                    "with cryptocurrency recovery or private credentials."
                ),
                "indicators": crypto_matches,
            })

            risk_score += 60

        # =====================================================
        # URL ANALYSIS
        # =====================================================

        urls = re.findall(
            r"https?://[^\s<>\"]+",
            text,
            re.IGNORECASE
        )

        suspicious_url_count = 0

        for url in urls:

            try:

                parsed = urlparse(url)

                hostname = parsed.hostname or ""

                hostname_lower = hostname.lower()

                suspicious_terms = [
                    "login",
                    "verify",
                    "secure",
                    "account",
                    "update",
                    "wallet",
                    "password",
                ]

                if any(
                    term in hostname_lower
                    for term in suspicious_terms
                ):

                    suspicious_url_count += 1

            except Exception:
                continue

        if suspicious_url_count > 0:

            findings.append({
                "type": "suspicious_url",
                "severity": "HIGH",
                "title": "Suspicious URL detected",
                "message": (
                    f"{suspicious_url_count} URL(s) contain "
                    "phishing-related indicators."
                ),
            })

            risk_score += 30

        # =====================================================
        # PHISHING LANGUAGE
        # =====================================================

        urgency_matches = [
            word
            for word in self.URGENCY_WORDS
            if word in normalized
        ]

        credential_matches = [
            word
            for word in self.CREDENTIAL_WORDS
            if word in normalized
        ]

        if urgency_matches and credential_matches:

            findings.append({
                "type": "phishing",
                "severity": "HIGH",
                "title": "Possible phishing language",
                "message": (
                    "The message combines urgency with credential "
                    "or account-verification language."
                ),
                "urgency_indicators": urgency_matches,
                "credential_indicators": credential_matches,
            })

            risk_score += 40

        # =====================================================
        # ATTACHMENT ANALYSIS
        # =====================================================

        dangerous_attachments = []

        for filename in attachments:

            filename_lower = str(filename).lower()

            for extension in self.EXECUTABLE_EXTENSIONS:

                if filename_lower.endswith(extension):

                    dangerous_attachments.append(filename)
                    break

        if dangerous_attachments:

            findings.append({
                "type": "dangerous_attachment",
                "severity": "HIGH",
                "title": "Executable attachment detected",
                "message": (
                    "The message contains an attachment type that "
                    "can execute code on a recipient's system."
                ),
                "attachments": dangerous_attachments,
            })

            risk_score += 40

        # =====================================================
        # FINAL SCORE
        # =====================================================

        risk_score = min(risk_score, 100)

        if risk_score >= 70:
            severity = "CRITICAL"

        elif risk_score >= 40:
            severity = "HIGH"

        elif risk_score >= 20:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        return {
            "safe": len(findings) == 0,
            "severity": severity,
            "risk_score": risk_score,
            "findings": findings,
            "urls_found": urls,
            "attachments_checked": attachments,
        }


# =============================================================
# DIRECT TEST
# =============================================================

if __name__ == "__main__":

    detector = ThreatDetector()

    test_email = """
    Hey,

    Please send me the wallet recovery phrase.
    My password: TestPassword123

    Also login here immediately:
    https://secure-login.example.com

    Thanks.
    """

    result = detector.analyze(
        test_email,
        attachments=["invoice.pdf"]
    )

    print()
    print("=" * 60)
    print("             MAILSCOPE CONTENT SCAN")
    print("=" * 60)

    print()
    print("Safe       :", result["safe"])
    print("Severity   :", result["severity"])
    print("Risk Score :", result["risk_score"])

    print()
    print("Findings:")

    for finding in result["findings"]:

        print()
        print(
            f"[{finding['severity']}] "
            f"{finding['title']}"
        )

        print(
            "    "
            + finding["message"]
        )

    print()
    print("=" * 60)