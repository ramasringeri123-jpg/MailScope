from email import policy
from email.parser import BytesParser
from email.message import Message
from pathlib import Path
from typing import Any


class EMLParser:
    """
    Parses a real .eml email file into a normalized structure
    that MailScope's security engines can analyze.
    """

    def parse_file(self, file_path: str) -> dict[str, Any]:

        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Email file not found: {path}"
            )

        if path.suffix.lower() != ".eml":
            raise ValueError(
                "MailScope currently accepts .eml files."
            )

        with path.open("rb") as email_file:
            message = BytesParser(
                policy=policy.default
            ).parse(email_file)

        return self._normalize(message, path)

    # ---------------------------------------------------------
    # NORMALIZE EMAIL
    # ---------------------------------------------------------

    def _normalize(
        self,
        message: Message,
        path: Path
    ) -> dict[str, Any]:

        headers = {}

        for key, value in message.items():

            headers[key] = str(value)

        body_parts = []
        html_parts = []

        attachments = []

        if message.is_multipart():

            for part in message.walk():

                content_type = part.get_content_type()
                disposition = part.get_content_disposition()

                filename = part.get_filename()

                # Attachment
                if disposition == "attachment" or filename:

                    payload = part.get_payload(
                        decode=True
                    )

                    attachments.append({
                        "filename": filename or "unknown",
                        "content_type": content_type,
                        "size": len(payload or b"")
                    })

                    continue

                # Text body
                if content_type == "text/plain":

                    try:
                        content = part.get_content()
                    except Exception:
                        content = ""

                    if content:
                        body_parts.append(
                            str(content)
                        )

                # HTML body
                elif content_type == "text/html":

                    try:
                        content = part.get_content()
                    except Exception:
                        content = ""

                    if content:
                        html_parts.append(
                            str(content)
                        )

        else:

            content_type = message.get_content_type()

            try:
                content = message.get_content()
            except Exception:
                content = ""

            if content_type == "text/html":
                html_parts.append(str(content))
            else:
                body_parts.append(str(content))

        body = "\n".join(body_parts)

        html_body = "\n".join(html_parts)

        return {
            "source_file": str(path.resolve()),

            "headers": headers,

            "sender": message.get(
                "From",
                ""
            ),

            "recipient": message.get(
                "To",
                ""
            ),

            "cc": message.get(
                "Cc",
                ""
            ),

            "subject": message.get(
                "Subject",
                ""
            ),

            "date": message.get(
                "Date",
                ""
            ),

            "message_id": message.get(
                "Message-ID",
                ""
            ),

            "body": body,

            "html_body": html_body,

            "attachments": attachments,

            "attachment_count": len(
                attachments
            )
        }


# =============================================================
# COMMAND-LINE TEST
# =============================================================

if __name__ == "__main__":

    import sys

    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            "python -m ingestion.eml_parser <email.eml>"
        )

        raise SystemExit(1)

    parser = EMLParser()

    result = parser.parse_file(
        sys.argv[1]
    )

    print()
    print("=" * 60)
    print("              MAILSCOPE EML PARSER")
    print("=" * 60)

    print()
    print("Source      :", result["source_file"])
    print("Sender      :", result["sender"])
    print("Recipient   :", result["recipient"])
    print("Subject     :", result["subject"])
    print("Date        :", result["date"])
    print("Message-ID  :", result["message_id"])

    print()
    print(
        "Attachments :",
        result["attachment_count"]
    )

    for attachment in result["attachments"]:

        print(
            "  -",
            attachment["filename"],
            "(",
            attachment["size"],
            "bytes )"
        )

    print()
    print("Body Preview")
    print("-" * 60)

    preview = result["body"].strip()

    if len(preview) > 1000:
        preview = preview[:1000] + "\n..."

    print(preview)

    print()
    print("=" * 60)