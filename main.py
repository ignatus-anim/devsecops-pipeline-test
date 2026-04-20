"""
Test DevSecOps application.

Deliberately pins older versions of several popular libraries so
the SCA stage (grype) has real vulnerabilities to report. Every
import below is exercised by at least one endpoint — the SBOM
should therefore list the full dependency tree, not just Flask.
"""

import base64
from io import BytesIO

import requests
import yaml
from cryptography.fernet import Fernet
from flask import Flask, jsonify, request
from PIL import Image

app = Flask(__name__)

# Demo-only in-memory key. Do not do this in production.
_fernet = Fernet(Fernet.generate_key())


@app.route("/")
def hello():
    return {"status": "ok"}


@app.route("/health")
def health():
    return {"status": "healthy", "service": "test-devsecops-app"}


@app.route("/parse-config", methods=["POST"])
def parse_config():
    """Parse a YAML config body. Exercises PyYAML."""
    body = request.get_data(as_text=True)
    try:
        parsed = yaml.safe_load(body)
    except yaml.YAMLError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"parsed": parsed})


@app.route("/fetch")
def fetch():
    """Fetch an upstream URL. Exercises requests + urllib3."""
    url = request.args.get("url", "https://httpbin.org/status/200")
    try:
        resp = requests.get(url, timeout=5)
    except requests.RequestException as exc:
        return jsonify({"error": str(exc)}), 502
    return jsonify({"status_code": resp.status_code, "url": url})


@app.route("/image-info", methods=["POST"])
def image_info():
    """Report basic metadata about an uploaded image. Exercises Pillow."""
    upload = request.files.get("image")
    if upload is None:
        return jsonify({"error": "no image uploaded"}), 400
    img = Image.open(BytesIO(upload.read()))
    return jsonify({"format": img.format, "size": img.size, "mode": img.mode})


@app.route("/encrypt", methods=["POST"])
def encrypt():
    """Symmetrically encrypt a plaintext payload. Exercises cryptography."""
    plaintext = request.get_data()
    token = _fernet.encrypt(plaintext)
    return jsonify({"ciphertext": base64.b64encode(token).decode()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
