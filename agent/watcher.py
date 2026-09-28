import os
import time
import shutil
import requests

# ============================================================
# MAILSCOPE
# AUTONOMOUS EMAIL WATCHER
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

INBOX_DIR = os.path.join(
    BASE_DIR,
    "data",
    "inbox"
)

INCIDENT_DIR = os.path.join(
    INBOX_DIR,
    "incidents"
)

PROCESSED_DIR = os.path.join(
    INBOX_DIR,
    "processed"
)

API_URL = "http://127.0.0.1:5000/analyze-email"

POLL_INTERVAL = 2

# Create required directories
os.makedirs(INBOX_DIR, exist_ok=True)
os.makedirs(INCIDENT_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)


# ============================================================
# DISPLAY
# ============================================================

def print_banner():

    print()
    print("=" * 64)
    print("                 MAILSCOPE")
    print("          AUTONOMOUS EMAIL WATCHER")
    print("=" * 64)
    print()

    print(f"Inbox         : {INBOX_DIR}")
    print(f"API           : {API_URL}")
    print("Threat Engine : ACTIVE")
    print("Watcher       : ACTIVE")

    print()
    print("Monitoring inbox for new .eml emails...")
    print("Press CTRL+C to stop.")
    print()

    print("=" * 64)


# ============================================================
# UNIQUE DESTINATION
# ============================================================

def get_unique_destination(directory, filename):

    destination = os.path.join(
        directory,
        filename
    )

    if not os.path.exists(destination):
        return destination

    name, extension = os.path.splitext(filename)

    counter = 1

    while True:

        new_name = f"{name}_{counter}{extension}"

        destination = os.path.join(
            directory,
            new_name
        )

        if not os.path.exists(destination):
            return destination

        counter += 1


# ============================================================
# MOVE THREAT TO INCIDENT STORAGE
# ============================================================

def isolate_email(filepath):

    filename = os.path.basename(filepath)

    destination = get_unique_destination(
        INCIDENT_DIR,
        filename
    )

    try:

        shutil.move(
            filepath,
            destination
        )

        print(
            f"[ACTION] EMAIL ISOLATED"
        )

        print(
            f"[ACTION] Incident: {destination}"
        )

    except FileNotFoundError:

        print(
            "[INFO] Email was already moved."
        )

    except Exception as error:

        print(
            f"[ERROR] Failed to isolate email: {error}"
        )


# ============================================================
# MOVE SAFE EMAIL TO PROCESSED STORAGE
# ============================================================

def archive_safe_email(filepath):

    filename = os.path.basename(filepath)

    destination = get_unique_destination(
        PROCESSED_DIR,
        filename
    )

    try:

        shutil.move(
            filepath,
            destination
        )

        print(
            "[ACTION] EMAIL PASSED SECURITY CHECK"
        )

        print(
            f"[ACTION] Email archived: {destination}"
        )

    except FileNotFoundError:

        print(
            "[INFO] Email was already processed."
        )

    except Exception as error:

        print(
            f"[ERROR] Failed to archive email: {error}"
        )


# ============================================================
# ANALYZE EMAIL
# ============================================================

def analyze_email(filepath):

    filename = os.path.basename(filepath)

    print()
    print("[NEW EMAIL DETECTED]")
    print(f"    File: {filename}")

    print()
    print("=" * 64)
    print("              MAILSCOPE AUTOMATIC ANALYSIS")
    print("=" * 64)

    try:

        with open(
            filepath,
            "rb"
        ) as email_file:

            response = requests.post(

                API_URL,

                files={
                    "file": (
                        filename,
                        email_file,
                        "message/rfc822"
                    )
                },

                timeout=30
            )

        if response.status_code != 200:

            print()
            print(
                "[ERROR] Security API returned:"
            )

            print(
                response.status_code
            )

            print(
                response.text
            )

            return

        result = response.json()

        security = result.get(
            "security",
            {}
        )

        safe = security.get(
            "safe",
            True
        )

        severity = security.get(
            "severity",
            "UNKNOWN"
        )

        risk_score = security.get(
            "risk_score",
            0
        )

        findings = security.get(
            "findings",
            []
        )

        print(
            f"Email       : {filename}"
        )

        print(
            f"Safe        : {safe}"
        )

        print(
            f"Severity    : {severity}"
        )

        print(
            f"Risk Score  : {risk_score} / 100"
        )

        print()
        print("FINDINGS")
        print("-" * 64)

        if findings:

            for finding in findings:

                finding_severity = finding.get(
                    "severity",
                    "INFO"
                )

                title = finding.get(
                    "title",
                    "Unknown finding"
                )

                message = finding.get(
                    "message",
                    ""
                )

                print(
                    f"[{finding_severity}] {title}"
                )

                print(
                    f"    {message}"
                )

                print()

        else:

            print(
                "No threats detected."
            )

        print(
            "=" * 64
        )

        # ====================================================
        # AUTOMATIC RESPONSE
        # ====================================================

        if not safe:

            print()
            print(
                "[ACTION] THREAT DETECTED"
            )

            isolate_email(
                filepath
            )

        else:

            print()

            archive_safe_email(
                filepath
            )

    except requests.exceptions.ConnectionError:

        print()
        print(
            "[ERROR] MailScope API is not running."
        )

        print(
            "Start it with:"
        )

        print(
            "python -m agent.api_server"
        )

    except Exception as error:

        print()
        print(
            f"[ERROR] Analysis failed: {error}"
        )


# ============================================================
# SCAN INBOX
# ============================================================

def scan_inbox():

    try:

        files = os.listdir(
            INBOX_DIR
        )

    except FileNotFoundError:

        os.makedirs(
            INBOX_DIR,
            exist_ok=True
        )

        return

    for filename in files:

        # Only process EML files
        if not filename.lower().endswith(".eml"):
            continue

        filepath = os.path.join(
            INBOX_DIR,
            filename
        )

        # Ignore directories
        if not os.path.isfile(filepath):
            continue

        # Analyze
        analyze_email(
            filepath
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print_banner()

    while True:

        scan_inbox()

        time.sleep(
            POLL_INTERVAL
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print()
        print("=" * 64)
        print("        MAILSCOPE WATCHER STOPPED")
        print("=" * 64)