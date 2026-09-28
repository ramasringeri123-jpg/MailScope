import asyncio
import ssl
from pathlib import Path

from aiosmtpd.controller import Controller


# ============================================================
# MAILSCOPE LAB CONFIGURATION
# ============================================================

# True  = SMTP with STARTTLS
# False = SMTP without STARTTLS (deliberately insecure test)
SECURE_MODE = True

HOST = "127.0.0.1"
PORT = 2525


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

CERT_FILE = BASE_DIR / "server.crt"
KEY_FILE = BASE_DIR / "server.key"


# ============================================================
# TEST MAIL HANDLER
# ============================================================

class TestMailHandler:

    async def handle_DATA(self, server, session, envelope):

        print()
        print("=" * 50)
        print("          TEST EMAIL RECEIVED")
        print("=" * 50)

        print(f"From : {envelope.mail_from}")
        print(f"To   : {envelope.rcpt_tos}")

        print()
        print("Message:")
        print(envelope.content.decode(errors="replace"))

        print("=" * 50)
        print()

        return "250 Message accepted by MailScope laboratory"


# ============================================================
# TLS CONFIGURATION
# ============================================================

def create_tls_context():

    if not CERT_FILE.exists():
        raise FileNotFoundError(
            f"Certificate not found: {CERT_FILE}"
        )

    if not KEY_FILE.exists():
        raise FileNotFoundError(
            f"Private key not found: {KEY_FILE}"
        )

    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

    context.load_cert_chain(
        certfile=str(CERT_FILE),
        keyfile=str(KEY_FILE)
    )

    return context


# ============================================================
# START SERVER
# ============================================================

def main():

    handler = TestMailHandler()

    tls_context = None

    if SECURE_MODE:

        print()
        print("Loading TLS certificate...")

        tls_context = create_tls_context()

    # --------------------------------------------------------
    # Create SMTP server
    # --------------------------------------------------------

    controller = Controller(
        handler,
        hostname=HOST,
        port=PORT,

        # If SECURE_MODE is True:
        # STARTTLS is available.
        #
        # If False:
        # STARTTLS is completely unavailable.
        tls_context=tls_context,

        require_starttls=False,
    )

    controller.start()

    print()
    print("=" * 60)
    print("             MAILSCOPE SMTP LABORATORY")
    print("=" * 60)

    print()
    print(f"Address       : {HOST}")
    print(f"Port          : {PORT}")

    print()

    if SECURE_MODE:

        print("MODE          : SECURE TEST")
        print("STARTTLS      : ENABLED")
        print("TLS           : AVAILABLE")
        print()
        print("Certificate   : server.crt")

    else:

        print("MODE          : INSECURE TEST")
        print("STARTTLS      : DISABLED")
        print("TLS           : NOT AVAILABLE")
        print()
        print("⚠ This mode intentionally simulates")
        print("  an SMTP server without STARTTLS.")

    print()
    print("This is a LOCAL MailScope laboratory.")
    print("No external mail server is being attacked.")
    print()
    print("Press CTRL+C to stop.")
    print("=" * 60)
    print()

    try:

        while True:
            asyncio.run(
                asyncio.sleep(1)
            )

    except KeyboardInterrupt:

        print()
        print("Stopping SMTP laboratory...")

        controller.stop()

        print("SMTP laboratory stopped.")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()