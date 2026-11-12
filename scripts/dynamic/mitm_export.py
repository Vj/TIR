"""mitmproxy addon that writes metadata-only traffic observations.

Start mitmdump with TIR_MITM_JSONL set to a file path. Bodies, headers, paths,
query strings, and cookies are intentionally excluded from the output.
"""
import json
import os
from datetime import datetime, timezone

OUTPUT_PATH = os.environ.get("TIR_MITM_JSONL")


class TIRMetadataExporter:
    def __init__(self):
        if not OUTPUT_PATH:
            raise RuntimeError("Set TIR_MITM_JSONL to the JSONL output path before starting mitmdump.")
        os.makedirs(os.path.dirname(os.path.abspath(OUTPUT_PATH)), exist_ok=True)

    def response(self, flow):
        request = flow.request
        tls_version = None
        try:
            tls_version = getattr(flow.server_conn, "tls_version", None)
        except Exception:
            pass
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scheme": str(request.scheme).lower(),
            "host": str(request.host).lower()[:253],
            "method": str(request.method).upper()[:12],
            "status_code": int(flow.response.status_code),
            "tls_version": str(tls_version)[:32] if tls_version else None,
            "proxy_response_observed": True,
        }
        with open(OUTPUT_PATH, "a", encoding="utf-8") as output:
            output.write(json.dumps(record, sort_keys=True) + "\n")


addons = [TIRMetadataExporter()]
