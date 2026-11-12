# engines/static/metadata_extractor.py
import os
import hashlib
import zipfile
from datetime import datetime
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class APKMetadataExtractor:
    """
    Extracts application binary metadata, SHA-256 integrity hashes,
    and signing certificate details from APK files.
    """

    def __init__(self, apk_path: str):
        self.apk_path = os.path.abspath(apk_path)

    def extract_metadata(self) -> Dict[str, Any]:
        """Calculates file metrics and extracts signing certificates."""
        file_size_bytes = os.path.getsize(self.apk_path)
        sha256_hash = self._compute_sha256()
        cert_details = self._extract_v1_signing_certificate()

        return {
            "apk_file_name": os.path.basename(self.apk_path),
            "file_size_human": f"{file_size_bytes / (1024 * 1024):.2f} MB ({file_size_bytes:,} bytes)",
            "file_size_bytes": file_size_bytes,
            "sha256": sha256_hash,
            "certificate": cert_details,
        }

    def _compute_sha256(self) -> str:
        sha256 = hashlib.sha256()
        with open(self.apk_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _extract_v1_signing_certificate(self) -> Dict[str, Any]:
        """Parses RSA/DSA certificate blocks found inside META-INF/."""
        default_cert_info = {
            "is_signed": False,
            "scheme": "Unsigned / Missing V1 Signature",
            "subject": "N/A",
            "issuer": "N/A",
            "serial_number": "N/A",
            "fingerprint_sha256": "N/A",
            "valid_from": "N/A",
            "valid_to": "N/A",
            "status": "Unverified",
        }

        try:
            with zipfile.ZipFile(self.apk_path, "r") as z:
                # Find signature block file in META-INF
                cert_files = [
                    f for f in z.namelist()
                    if f.startswith("META-INF/") and f.upper().endswith((".RSA", ".DSA", ".EC"))
                ]

                if not cert_files:
                    return default_cert_info

                cert_data = z.read(cert_files[0])
                
                # Attempt X.509 certificate extraction from PKCS#7 block or raw DER
                cert = None
                try:
                    # In many Android APKs, the certificate is stored as raw DER or PKCS#7
                    cert = x509.load_der_x509_certificate(cert_data, default_backend())
                except Exception:
                    # Fallback: scan for embedded DER sequence within PKCS#7 envelope
                    cert = self._find_embedded_x509_der(cert_data)

                if cert:
                    now = datetime.utcnow()
                    is_valid = cert.not_valid_before <= now <= cert.not_valid_after
                    
                    return {
                        "is_signed": True,
                        "scheme": f"v1 (JAR Signature) via {cert_files[0]}",
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "serial_number": hex(cert.serial_number),
                        "fingerprint_sha256": cert.fingerprint(hashlib.sha256()).hex(),
                        "valid_from": cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "valid_to": cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "status": "Valid (Active)" if is_valid else "Expired / Invalid Time Window",
                    }
                else:
                    return {
                        "is_signed": True,
                        "scheme": f"v1 Block Present ({cert_files[0]})",
                        "subject": "Parsed via raw envelope",
                        "issuer": "Embedded signer",
                        "serial_number": "N/A",
                        "fingerprint_sha256": hashlib.sha256(cert_data).hexdigest(),
                        "valid_from": "N/A",
                        "valid_to": "N/A",
                        "status": "Present (Signature Block Detected)",
                    }
        except Exception as e:
            default_cert_info["status"] = f"Extraction error: {str(e)}"
            return default_cert_info

    def _find_embedded_x509_der(self, data: bytes) -> Optional[x509.Certificate]:
        """Scans byte sequence to locate standard ASN.1 DER sequence boundaries."""
        for i in range(len(data) - 100):
            if data[i] == 0x30 and data[i + 1] in (0x82, 0x83):
                try:
                    return x509.load_der_x509_certificate(data[i:], default_backend())
                except Exception:
                    continue
        return None