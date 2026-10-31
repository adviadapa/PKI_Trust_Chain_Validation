from datetime import datetime, timedelta, timezone
from pathlib import Path
import base64

from flask import Flask, jsonify, render_template
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
ROOT = Path(__file__).parent
KEYS = ROOT / "keys"
CERTS = ROOT / "certificates"
KEYS.mkdir(exist_ok=True)
CERTS.mkdir(exist_ok=True)

def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def name(common_name):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

def build_certificate(subject, issuer, public_key, issuer_key, serial, is_ca):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca and subject != issuer else None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=not is_ca,
            data_encipherment=False, key_agreement=False, key_cert_sign=is_ca,
            crl_sign=is_ca, encipher_only=False, decipher_only=False
        ), critical=True)
    )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())

def save_key(key, path):
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

def save_cert(cert, path):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

def ensure_demo_chain():
    # Create a fresh, self-contained demo chain each time the app starts.
    root_key = new_key()
    intermediate_key = new_key()
    user_key = new_key()
    attacker_key = new_key()

    root_name = name("Demo Root CA")
    intermediate_name = name("Demo Intermediate CA")
    user_name = name("Alice End User")
    attacker_name = name("Untrusted Attacker")

    root_cert = build_certificate(root_name, root_name, root_key.public_key(), root_key, 1001, True)
    intermediate_cert = build_certificate(intermediate_name, root_name, intermediate_key.public_key(), root_key, 1002, True)
    user_cert = build_certificate(user_name, intermediate_name, user_key.public_key(), intermediate_key, 1003, False)
    # This certificate claims to be issued by the Intermediate CA but is signed by an attacker key.
    fake_cert = build_certificate(user_name, intermediate_name, attacker_key.public_key(), attacker_key, 1004, False)

    for filename, key in [
        ("root_ca_key.pem", root_key), ("intermediate_ca_key.pem", intermediate_key),
        ("end_user_key.pem", user_key), ("attacker_key.pem", attacker_key)
    ]:
        save_key(key, KEYS / filename)
    for filename, cert in [
        ("root_ca.crt", root_cert), ("intermediate_ca.crt", intermediate_cert),
        ("end_user.crt", user_cert), ("fake_end_user.crt", fake_cert)
    ]:
        save_cert(cert, CERTS / filename)

    return root_cert, intermediate_cert, user_cert, fake_cert

def verify_signature(child_cert, issuer_cert):
    if child_cert.issuer != issuer_cert.subject:
        return False, "Issuer name does not match the issuer certificate subject."
    try:
        issuer_cert.public_key().verify(
            child_cert.signature,
            child_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            child_cert.signature_hash_algorithm
        )
        return True, "Signature verified."
    except (InvalidSignature, ValueError, TypeError):
        return False, "Signature verification failed."

def is_current(cert):
    now = datetime.now(timezone.utc)
    # cryptography versions differ in whether *_utc is available.
    start = getattr(cert, "not_valid_before_utc", None)
    end = getattr(cert, "not_valid_after_utc", None)
    if start is None:
        start = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if end is None:
        end = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return start <= now <= end

def validate_chain(root_cert, intermediate_cert, end_user_cert):
    checks = []
    checks.append({
        "name": "End-user certificate → Intermediate CA",
        "ok": end_user_cert.issuer == intermediate_cert.subject,
        "detail": "Issuer name matches Intermediate CA." if end_user_cert.issuer == intermediate_cert.subject else "Issuer name mismatch."
    })
    ok, detail = verify_signature(end_user_cert, intermediate_cert)
    checks.append({"name": "End-user signature", "ok": ok, "detail": detail})

    checks.append({
        "name": "Intermediate CA → Root CA",
        "ok": intermediate_cert.issuer == root_cert.subject,
        "detail": "Issuer name matches Root CA." if intermediate_cert.issuer == root_cert.subject else "Issuer name mismatch."
    })
    ok, detail = verify_signature(intermediate_cert, root_cert)
    checks.append({"name": "Intermediate CA signature", "ok": ok, "detail": detail})

    ok = root_cert.issuer == root_cert.subject
    checks.append({"name": "Root CA is self-issued", "ok": ok, "detail": "Root issuer and subject match." if ok else "Root issuer and subject do not match."})

    for label, cert in [("Root CA validity", root_cert), ("Intermediate CA validity", intermediate_cert), ("End-user validity", end_user_cert)]:
        ok = is_current(cert)
        checks.append({"name": label, "ok": ok, "detail": "Certificate is within its validity period." if ok else "Certificate is expired or not yet valid."})

    try:
        root_constraints = root_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        intermediate_constraints = intermediate_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        user_constraints = end_user_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        root_ok = root_constraints.ca
        intermediate_ok = intermediate_constraints.ca
        user_ok = not user_constraints.ca
    except x509.ExtensionNotFound:
        root_ok = intermediate_ok = user_ok = False

    checks.extend([
        {"name": "Root CA constraints", "ok": root_ok, "detail": "Root is marked as a CA." if root_ok else "Root is not marked as a CA."},
        {"name": "Intermediate CA constraints", "ok": intermediate_ok, "detail": "Intermediate is marked as a CA." if intermediate_ok else "Intermediate is not marked as a CA."},
        {"name": "End-user constraints", "ok": user_ok, "detail": "End-user certificate is not a CA." if user_ok else "End-user certificate is incorrectly marked as a CA."},
    ])
    trusted_root = root_cert.subject == name("Demo Root CA")
    checks.append({"name": "Trusted Root CA", "ok": trusted_root, "detail": "Root matches this demo's configured trust anchor." if trusted_root else "Root is not the configured trust anchor."})

    return {"valid": all(c["ok"] for c in checks), "checks": checks}

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/validate")
def validate():
    root, intermediate, user, _ = ensure_demo_chain()
    result = validate_chain(root, intermediate, user)
    result["certificate_chain"] = [
        {"level": "Root CA", "subject": root.subject.rfc4514_string(), "issuer": root.issuer.rfc4514_string(), "serial": str(root.serial_number)},
        {"level": "Intermediate CA", "subject": intermediate.subject.rfc4514_string(), "issuer": intermediate.issuer.rfc4514_string(), "serial": str(intermediate.serial_number)},
        {"level": "End User", "subject": user.subject.rfc4514_string(), "issuer": user.issuer.rfc4514_string(), "serial": str(user.serial_number)},
    ]
    result["message"] = "Certificate chain is valid." if result["valid"] else "Certificate chain validation failed."
    return jsonify(result)

@app.route("/api/validate-tampered")
def validate_tampered():
    root, intermediate, _, fake = ensure_demo_chain()
    result = validate_chain(root, intermediate, fake)
    result["message"] = "Unexpected: fake certificate accepted." if result["valid"] else "Fake certificate correctly rejected."
    return jsonify(result)

if __name__ == "__main__":
    print("PKI Trust Chain Validation running at http://127.0.0.1:5000")
    app.run(debug=True)
