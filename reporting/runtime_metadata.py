"""Installed APK metadata collection for ADB-only audits."""
import hashlib
import os
import re
import subprocess
import tempfile


def collect_installed_metadata(package, device=None, adb_path="adb"):
    result = {"version_name": "Unavailable", "version_code": "Unavailable",
              "target_sdk": "Unavailable", "min_sdk": "Unavailable",
              "file_size": "Unavailable", "sha256": "Unavailable",
              "cert_status": "Unverified", "cert_fingerprint": "Unavailable"}
    command = [adb_path] + (["-s", device] if device else [])
    def adb(args, timeout=30):
        return subprocess.run(command + args, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout, check=False)
    try:
        dump = adb(["shell", "dumpsys", "package", package]).stdout
        patterns = {"version_name": r"versionName=([^\s]+)",
                    "version_code": r"versionCode=([^\s]+)",
                    "target_sdk": r"targetSdk=(\d+)", "min_sdk": r"minSdk=(\d+)"}
        for field, pattern in patterns.items():
            match = re.search(pattern, dump)
            if match:
                result[field] = match.group(1)
        paths = adb(["shell", "pm", "path", package]).stdout.splitlines()
        base_path = next((line.partition(":")[2].strip() for line in paths
                          if line.startswith("package:") and line.endswith("base.apk")), None)
        if base_path:
            with tempfile.TemporaryDirectory(prefix="tir-apk-") as temp:
                local_path = os.path.join(temp, "base.apk")
                pull = adb(["pull", base_path, local_path], timeout=90)
                if pull.returncode == 0 and os.path.isfile(local_path):
                    result["file_size"] = str(os.path.getsize(local_path)) + " bytes"
                    digest = hashlib.sha256()
                    with open(local_path, "rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(chunk)
                    result["sha256"] = digest.hexdigest()
                    signer = subprocess.run(["apksigner", "verify", "--print-certs", local_path],
                        capture_output=True, text=True, encoding="utf-8", errors="replace",
                        timeout=30, check=False)
                    match = re.search(r"certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", signer.stdout)
                    if signer.returncode == 0 and match:
                        result["cert_status"] = "Verified"
                        result["cert_fingerprint"] = match.group(1)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return result
