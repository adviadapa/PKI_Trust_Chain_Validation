# PKI Trust Chain Validation — CNS Project

A beginner-friendly full-stack project with a Flask/Python backend and HTML, CSS, and JavaScript frontend. It simulates:

**Trusted Root CA → Intermediate CA → End-user certificate**

The backend verifies certificate issuer names, RSA signatures using SHA-256, certificate validity periods, CA constraints, and the configured trusted root. A second test uses a fake certificate signed by an untrusted key and should reject it.

## Requirements

- Python 3.10 or newer
- VS Code
- Internet only for the first-time installation of Python packages

## Run in VS Code (Windows)

1. Extract the ZIP file.
2. Open VS Code.
3. Select **File → Open Folder** and choose the extracted `PKI_Trust_Chain_Validation` folder.
4. Open **Terminal → New Terminal**.
5. Create a virtual environment:

   ```powershell
   py -m venv .venv
   ```

6. Activate it in PowerShell:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, you can use Command Prompt instead:

   ```bat
   .venv\Scripts\activate.bat
   ```

7. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

8. Start the app:

   ```powershell
   python app.py
   ```

9. Open this address in your browser: **http://127.0.0.1:5000**

Keep the terminal open while using the site. Stop the server with `Ctrl + C`.

## How to test

- Click **Validate genuine chain**. The result should be valid and the checks should pass.
- Click **Test fake certificate**. The fake end-user certificate should be rejected because its signature does not verify against the Intermediate CA's public key.

The app generates demo RSA keys and certificates locally when a test is run. Files are written into `keys/` and `certificates/`; these are demo-only private keys and must never be used for real identities or production services.

## Project structure

```text
PKI_Trust_Chain_Validation/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── app.js
├── keys/              # generated when you run the app
└── certificates/      # generated when you run the app
```

## Concepts for your viva

- **PKI:** A framework for creating, distributing, and validating digital certificates.
- **Root CA:** The top-level authority configured as trusted.
- **Intermediate CA:** A CA certificate signed by the Root CA; it issues end-user certificates.
- **End-user certificate:** The certificate whose chain is being validated.
- **Digital signature check:** The issuer's public key verifies the signature on the child certificate.
- **Trust chain:** The verifier checks the end-user certificate with the Intermediate CA, then checks the Intermediate CA with the Root CA.
- **Fake certificate test:** Shows why a matching issuer name alone is not enough; the cryptographic signature must also validate.

## Scope

This is an educational simulation, not a production-grade RFC 5280 path validator. It does not implement revocation checking (CRL/OCSP), certificate policies, name constraints, or a browser trust store.
