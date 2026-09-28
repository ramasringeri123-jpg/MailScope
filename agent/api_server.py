from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import tempfile
import traceback

# ============================================================
# MAILSCOPE SECURITY AGENT - API SERVER
# ============================================================

# Make project root available
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import threat detection engine
from detection.threat_detector import ThreatDetector

# Import EML parser/analyzer if available
try:
    from ingestion.eml_parser import EMLParser
except ImportError:
    EMLParser = None

try:
    from ingestion.email_analyzer import EmailAnalyzer
except ImportError:
    EmailAnalyzer = None


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)
CORS(app)

detector = ThreatDetector()


# ============================================================
# BASIC INFORMATION
# ============================================================

VERSION = "1.0"
SERVICE_NAME = "MailScope Security Agent"


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "service": SERVICE_NAME,
        "version": VERSION,
        "engine": "active"
    })


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "service": SERVICE_NAME,
        "version": VERSION,
        "status": "online",
        "endpoints": {
            "health": "/health",
            "analyze": "/analyze",
            "analyze_email": "/analyze-email"
        }
    })


# ============================================================
# TEXT EMAIL ANALYSIS
# ============================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    try:

        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "success": False,
                "error": "JSON request body required"
            }), 400

        message = data.get("message", "")

        if not message:
            return jsonify({
                "success": False,
                "error": "Message field is required"
            }), 400

        result = detector.analyze(message)

        return jsonify({
            "success": True,
            "engine": SERVICE_NAME,
            "result": result
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e),
            "type": type(e).__name__
        }), 500


# ============================================================
# EML FILE ANALYSIS
# ============================================================

@app.route("/analyze-email", methods=["POST"])
def analyze_email():

    temp_path = None

    try:

        # ----------------------------------------------------
        # Check uploaded file
        # ----------------------------------------------------

        if "file" not in request.files:

            return jsonify({
                "success": False,
                "error": "No email file supplied"
            }), 400

        uploaded_file = request.files["file"]

        if not uploaded_file.filename:

            return jsonify({
                "success": False,
                "error": "Empty filename"
            }), 400

        filename = uploaded_file.filename.lower()

        if not filename.endswith(".eml"):

            return jsonify({
                "success": False,
                "error": "Only .eml files are supported"
            }), 400

        # ----------------------------------------------------
        # Save temporarily
        # ----------------------------------------------------

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".eml"
        ) as temp_file:

            uploaded_file.save(temp_file.name)
            temp_path = temp_file.name

        # ----------------------------------------------------
        # Parse EML
        # ----------------------------------------------------

        parsed_email = None

        if EMLParser is not None:

            parser = EMLParser()

            parsed_email = parser.parse_file(temp_path)

        # ----------------------------------------------------
        # Extract email content
        # ----------------------------------------------------

        sender = ""
        recipient = ""
        subject = ""
        body = ""
        attachments = []

        if isinstance(parsed_email, dict):

            sender = parsed_email.get(
                "sender",
                parsed_email.get("from", "")
            )

            recipient = parsed_email.get(
                "recipient",
                parsed_email.get("to", "")
            )

            subject = parsed_email.get(
                "subject",
                ""
            )

            body = parsed_email.get(
                "body",
                parsed_email.get("text", "")
            )

            attachments = parsed_email.get(
                "attachments",
                []
            )

        # ----------------------------------------------------
        # Fallback: use raw EML if parser unavailable
        # ----------------------------------------------------

        if not body:

            with open(
                temp_path,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as f:

                raw_email = f.read()

            body = raw_email

        # ----------------------------------------------------
        # Analyze email body
        # ----------------------------------------------------

        result = detector.analyze(body)

        # ----------------------------------------------------
        # Return complete security result
        # ----------------------------------------------------

        response = {
            "success": True,
            "engine": SERVICE_NAME,

            "email": {
                "filename": uploaded_file.filename,
                "sender": sender,
                "recipient": recipient,
                "subject": subject,
                "attachments": attachments
            },

            "security": result
        }

        return jsonify(response)

    except Exception as e:

        print("\n[MAILSCOPE ERROR]")
        traceback.print_exc()

        return jsonify({
            "success": False,
            "error": str(e),
            "type": type(e).__name__
        }), 500

    finally:

        # ----------------------------------------------------
        # Remove temporary file
        # ----------------------------------------------------

        if temp_path and os.path.exists(temp_path):

            try:
                os.remove(temp_path)
            except Exception:
                pass


# ============================================================
# SERVER STATUS
# ============================================================

@app.route("/status", methods=["GET"])
def status():

    return jsonify({

        "system": "MailScope",

        "status": "ACTIVE",

        "security_engine": "ACTIVE",

        "threat_detector": "ACTIVE",

        "email_ingestion": (
            "ACTIVE"
            if EMLParser is not None
            else "LIMITED"
        ),

        "version": VERSION

    })


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("                 MAILSCOPE")
    print("          EMAIL SECURITY AGENT")
    print("=" * 60)

    print()
    print("Service       : ONLINE")
    print("Threat Engine : ACTIVE")
    print("Email Parser  : " +
          ("ACTIVE" if EMLParser is not None else "LIMITED"))

    print()
    print("API ENDPOINTS")
    print("-" * 60)
    print("Health        : http://127.0.0.1:5000/health")
    print("Status        : http://127.0.0.1:5000/status")
    print("Analyze       : POST /analyze")
    print("Analyze EML   : POST /analyze-email")
    print()

    print("=" * 60)
    print("        MAILSCOPE SECURITY AGENT READY")
    print("=" * 60)
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True
    )