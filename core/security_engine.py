class SecurityEngine:
    """
    Converts technical TLS and certificate information
    into security findings and a risk assessment.
    """

    def analyze(self, scan_result, certificate_result):

        findings = []
        score = 0

        # -----------------------------
        # Connection
        # -----------------------------

        if not scan_result.get("connected"):
            findings.append({
                "severity": "CRITICAL",
                "title": "Connection failed",
                "description": "Mail server could not be reached."
            })

            score += 100
            return self._build_result(score, findings)

        # -----------------------------
        # STARTTLS
        # -----------------------------

        if not scan_result.get("starttls"):
            findings.append({
                "severity": "CRITICAL",
                "title": "STARTTLS unavailable",
                "description": "The SMTP server does not advertise STARTTLS."
            })

            score += 40

        # -----------------------------
        # TLS version
        # -----------------------------

        tls_version = scan_result.get("tls_version")

        if tls_version == "TLSv1" or tls_version == "TLSv1.1":

            findings.append({
                "severity": "CRITICAL",
                "title": "Deprecated TLS version",
                "description": f"{tls_version} is deprecated."
            })

            score += 40

        elif tls_version == "TLSv1.2":

            findings.append({
                "severity": "LOW",
                "title": "TLS 1.2 detected",
                "description": (
                    "TLS 1.2 is supported. TLS 1.3 is preferred "
                    "where available."
                )
            })

            score += 5

        elif tls_version == "TLSv1.3":

            findings.append({
                "severity": "INFO",
                "title": "Modern TLS version",
                "description": "TLS 1.3 is currently negotiated."
            })

        # -----------------------------
        # Cipher
        # -----------------------------

        cipher = scan_result.get("cipher")

        if cipher:

            cipher_name = cipher[0]

            weak_keywords = [
                "RC4",
                "3DES",
                "DES",
                "NULL",
                "EXPORT",
                "MD5"
            ]

            if any(
                keyword in cipher_name.upper()
                for keyword in weak_keywords
            ):

                findings.append({
                    "severity": "HIGH",
                    "title": "Weak cipher detected",
                    "description": cipher_name
                })

                score += 30

            else:

                findings.append({
                    "severity": "INFO",
                    "title": "Strong cipher negotiated",
                    "description": cipher_name
                })

        # -----------------------------
        # Certificate
        # -----------------------------

        if certificate_result.get("success"):

            validity = certificate_result.get("validity")

            if validity == "EXPIRED":

                findings.append({
                    "severity": "CRITICAL",
                    "title": "Certificate expired",
                    "description": "The server certificate is expired."
                })

                score += 40

            elif validity == "NOT_YET_VALID":

                findings.append({
                    "severity": "HIGH",
                    "title": "Certificate not yet valid",
                    "description": (
                        "The certificate validity period "
                        "has not started."
                    )
                })

                score += 25

            elif validity == "VALID":

                findings.append({
                    "severity": "INFO",
                    "title": "Certificate is valid",
                    "description": (
                        "The certificate is currently within "
                        "its validity period."
                    )
                })

            # -------------------------
            # Self-signed certificate
            # -------------------------

            if certificate_result.get("self_signed"):

                findings.append({
                    "severity": "MEDIUM",
                    "title": "Self-signed certificate",
                    "description": (
                        "The certificate is self-signed. "
                        "Trust should be evaluated according "
                        "to the deployment environment."
                    )
                })

                score += 15

            # -------------------------
            # RSA key size
            # -------------------------

            key_type = certificate_result.get("key_type")
            key_size = certificate_result.get("key_size")

            if key_type == "RSA" and key_size:

                if key_size < 2048:

                    findings.append({
                        "severity": "HIGH",
                        "title": "Weak RSA key",
                        "description": (
                            f"RSA key size is {key_size} bits."
                        )
                    })

                    score += 30

                else:

                    findings.append({
                        "severity": "INFO",
                        "title": "RSA key size acceptable",
                        "description": f"RSA-{key_size} detected."
                    })

        # -----------------------------
        # Final score
        # -----------------------------

        score = min(score, 100)

        return self._build_result(score, findings)

    @staticmethod
    def _build_result(score, findings):

        if score >= 70:
            risk = "CRITICAL"

        elif score >= 40:
            risk = "HIGH"

        elif score >= 20:
            risk = "MEDIUM"

        else:
            risk = "LOW"

        return {
            "score": score,
            "risk": risk,
            "findings": findings
        }


if __name__ == "__main__":

    print("MailScope Security Engine")
    print("Security analysis module loaded successfully.")