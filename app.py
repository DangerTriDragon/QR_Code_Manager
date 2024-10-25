from flask import Flask, render_template, request, jsonify, send_file
import cv2
import os
import vt
import re
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from markupsafe import escape
import qrcode
from io import BytesIO
import logging
from typing import Optional, Tuple, Dict, Any

# Load environment variables from .env file
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
class Config:
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    UPLOAD_FOLDER = "uploads/"
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

app.config.from_object(Config)

# Ensure the upload folder exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

def allowed_file(filename: str) -> bool:
    """Check if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def scan_qr_code(image_path: str) -> Optional[str]:
    """
    Scan QR code from image and return the decoded data.
    
    Args:
        image_path (str): Path to the image file
        
    Returns:
        Optional[str]: Decoded QR code data or None if no QR code is found
    """
    try:
        img = cv2.imread(image_path)
        if img is None:
            logger.error(f"Failed to load image: {image_path}")
            return None
            
        detector = cv2.QRCodeDetector()
        data, vertices, _ = detector.detectAndDecode(img)
        return data if data else None
    except Exception as e:
        logger.error(f"Error scanning QR code: {str(e)}")
        return None

def is_bank_url(url: str) -> bool:
    """
    Check if the scanned URL contains any bank-related terms.
    
    Args:
        url (str): URL to check
        
    Returns:
        bool: True if URL contains bank-related terms, False otherwise
    """
    url = url.lower()
    url = re.sub(r"[^\w\s@]", "", url)

    bank_terms = {
        "@upi", "@jupiteraxis", "@oksbi", "@okhdfcbank",
        "@hdfcbank", "@icici", "@dbs", "@fbl",
        "@oksbi", "@okaxis", "@okicici"
    }

    return any(term in url for term in bank_terms)

def check_url_virustotal(api_key: str, url: str) -> str:
    """
    Check URL on VirusTotal and return formatted HTML results.
    
    Args:
        api_key (str): VirusTotal API key
        url (str): URL to check
        
    Returns:
        str: Formatted HTML with VirusTotal results
    """
    if not api_key:
        logger.error("VirusTotal API key not configured")
        return "<p>Error: VirusTotal API key not configured</p>"

    client = vt.Client(api_key)
    try:
        url_id = vt.url_id(url)
        analysis = client.get_object(f"/urls/{url_id}")
        stats = analysis.last_analysis_stats

        return f"""
        <div class="results-container">
            <div class="result-card malicious">
                <h3>Malicious</h3>
                <div class="icon">❌</div>
                <p>{stats['malicious']}</p>
            </div>
            <div class="result-card suspicious">
                <h3>Suspicious</h3>
                <div class="icon">⚠️</div>
                <p>{stats['suspicious']}</p>
            </div>
            <div class="result-card harmless">
                <h3>Harmless</h3>
                <div class="icon">✅</div>
                <p>{stats['harmless']}</p>
            </div>
            <div class="result-card undetected">
                <h3>Undetected</h3>
                <div class="icon">❓</div>
                <p>{stats['undetected']}</p>
            </div>
        </div>
        """
    except Exception as e:
        logger.error(f"VirusTotal API error: {str(e)}")
        return f"<p>Error checking URL: {escape(str(e))}</p>"
    finally:
        client.close()

# Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    """Handle file upload and QR code scanning."""
    if "file" not in request.files:
        return jsonify(error="No file uploaded"), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify(error="No selected file"), 400

    if not allowed_file(file.filename):
        return jsonify(error="File type not allowed"), 400

    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        scanned_url = scan_qr_code(file_path)
        if not scanned_url:
            return jsonify(error="No QR code found in the image"), 400

        # Clean up the uploaded file
        os.remove(file_path)

        bank_message = ""
        if is_bank_url(scanned_url):
            bank_message = "<p><strong>Warning:</strong><mark> This QR code is associated with a bank URL. Proceed with caution.</mark></p>"

        result_html = check_url_virustotal(Config.VIRUSTOTAL_API_KEY, scanned_url)
        response_html = f"""
        <p>Scanned URL: <a href="{escape(scanned_url)}" target="_blank" rel="noopener noreferrer">{escape(scanned_url)}</a></p>
        {bank_message}
        {result_html}
        """
        return jsonify(result=response_html)

    except Exception as e:
        logger.error(f"Error processing upload: {str(e)}")
        return jsonify(error="An error occurred while processing the file"), 500

@app.route("/generate_qr", methods=["POST"])
def generate_qr():
    """Generate QR code from URL."""
    url = request.form.get("url")
    if not url:
        return jsonify(error="No URL provided"), 400

    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(url)
        qr.make(fit=True)

        buffer = BytesIO()
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img.save(buffer, "PNG")
        buffer.seek(0)

        return send_file(
            buffer,
            mimetype="image/png",
            as_attachment=True,
            download_name="qrcode.png",
        )

    except Exception as e:
        logger.error(f"Error generating QR code: {str(e)}")
        return jsonify(error=f"Failed to generate QR code"), 500

if __name__ == "__main__":
    app.run(debug=False)  # Set debug=False in production


print("test")
