from flask import Flask, render_template, request, jsonify
import cv2
from pyzbar.pyzbar import decode
import os
import vt
import re
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from markupsafe import escape
import qrcode
from io import BytesIO
from flask import send_file


# Load environment variables from .env file
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)

# VirusTotal API key (Use environment variable in production for security)
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Path to save uploaded images
UPLOAD_FOLDER = "uploads/"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Function to scan QR code from image
def scan_qr_code(image_path):
    img = cv2.imread(image_path)
    qr_codes = decode(img)
    for qr_code in qr_codes:
        data = qr_code.data.decode("utf-8")
        return data
    return None


# List of bank-related terms
import re


def is_bank_url(url):
    """Check if the scanned URL contains any bank-related terms."""
    # Convert URL to lowercase to ensure case-insensitive matching
    url = url.lower()

    # Strip out unwanted characters from the URL (like special chars)
    url = re.sub(r"[^\w\s@]", "", url)

    # List of bank-related terms
    bank_terms = [
        "@upi",
        "@jupiteraxis",
        "@oksbi",
        "@okhdfcbank",
        "@hdfcbank",
        "@icici",
        "@dbs",
        "@fbl",
        "@oksbi",
        "@okaxis",
        "@okicici",
    ]

    # Check if any bank term is in the cleaned URL
    for term in bank_terms:
        if term in url:
            return True
    return False


# Function to check URL on VirusTotal
def check_url_virustotal(api_key, url):
    client = vt.Client(api_key)
    try:
        url_id = vt.url_id(url)
        analysis = client.get_object(f"/urls/{url_id}")
        stats = analysis.last_analysis_stats
        harmless = stats["harmless"]
        malicious = stats["malicious"]
        suspicious = stats["suspicious"]
        undetected = stats["undetected"]

        result_html = f"""
        <div class="results-container">
            <div class="result-card malicious">
                <h3>Malicious</h3>
                <div class="icon">❌</div>
                <p>{malicious}</p>
            </div>
            <div class="result-card suspicious">
                <h3>Suspicious</h3>
                <div class="icon">⚠️</div>
                <p>{suspicious}</p>
            </div>
            <div class="result-card harmless">
                <h3>Harmless</h3>
                <div class="icon">✅</div>
                <p>{harmless}</p>
            </div>
            <div class="result-card undetected">
                <h3>Undetected</h3>
                <div class="icon">❓</div>
                <p>{undetected}</p>
            </div>
        </div>
        """
        return result_html
    except Exception as e:
        return f"Error: {e}"
    finally:
        client.close()


# Route for the homepage
@app.route("/")
def index():
    return render_template("index.html")


# Route to handle the file upload and QR scanning
# Function to scan QR code and return HTML response
@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify(error="No file part"), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify(error="No selected file"), 400

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        # Scan the QR code from the uploaded image
        scanned_url = scan_qr_code(file_path)

        if scanned_url:
            # Check if the scanned URL contains bank-related terms
            bank_message = ""
            if is_bank_url(scanned_url):
                bank_message = "<p><strong>Note:</strong><mark> This QR code is associated with a bank URL. Proceed with caution.</mark></p>"

            # Check the scanned URL with VirusTotal and return results
            result_html = check_url_virustotal(API_KEY, scanned_url)

            # Combine the scanned URL, bank warning, and VirusTotal results in the response
            response_html = f"""
            <p>Scanned URL: <a href="{escape(scanned_url)}" target="_blank">{escape(scanned_url)}</a></p>
            {bank_message}
            {result_html}
            """
            return jsonify(result=response_html)
        else:
            return jsonify(error="No QR code found in the image."), 400


@app.route("/generate_qr", methods=["POST"])
def generate_qr():
    url = request.form.get("url")
    if url:
        try:
            # Generate the QR code
            qr_img = qrcode.make(url)
            buffer = BytesIO()
            qr_img.save(buffer, "PNG")
            buffer.seek(0)

            # Send the file as a download response
            return send_file(
                buffer,
                mimetype="image/png",
                as_attachment=True,
                download_name="qrcode.png",
            )

        except Exception as e:
            return jsonify(error=f"Failed to generate QR code: {str(e)}"), 500
    return jsonify(error="No URL provided"), 400


if __name__ == "__main__":
    # Run the Flask web server
    app.run(debug=True)
