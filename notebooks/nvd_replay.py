"""Serve exact recorded NVD responses, or select the live endpoint explicitly."""

from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Lock, Thread
from urllib.parse import parse_qs, urlsplit


class NVDSource:
    """Own a loopback-only recording server and its request audit."""

    def __init__(self, mode: str) -> None:
        """Choose recorded or live access without fallback between modes."""
        if mode not in {"recorded", "live"}:
            raise ValueError('DATA_MODE must be "recorded" or "live".')
        self.mode = mode
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.requests: Counter[str] = Counter()
        self.unexpected: list[str] = []
        self.server = None
        self.thread = None
        self.manifest = None
        if mode == "live":
            self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            self.provenance = f"Live NVD requests started {self.started_at}"
            return
        directory = Path(__file__).resolve().parent / "fixtures"
        self.manifest = json.loads((directory / "manifest.json").read_text())
        responses = {}
        for entry in self.manifest["records"]:
            body = (directory / entry["file"]).read_bytes()
            if sha256(body).hexdigest() != entry["sha256"]:
                raise ValueError(f"Recorded response digest mismatch: {entry['file']}")
            responses[entry["id"]] = body
        owner = self
        lock = Lock()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                """Accept only exact single-CVE lookup requests from this fixture."""
                parsed = urlsplit(self.path)
                query = parse_qs(parsed.query, keep_blank_values=True)
                values = query.get("cveId", [])
                if (
                    parsed.path != "/rest/json/cves/2.0"
                    or set(query) != {"cveId"}
                    or len(values) != 1
                    or values[0] not in responses
                ):
                    with lock:
                        owner.unexpected.append("Unexpected recorded-ID request")
                    self.send_error(404, "Request is outside the recorded CVE set")
                    return
                cve_id = values[0]
                with lock:
                    owner.requests[cve_id] += 1
                body = responses[cve_id]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args) -> None:
                """Keep request bodies and server logs out of saved outputs."""

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}/rest/json/cves/2.0"
        times = sorted(entry["captured_at_utc"] for entry in self.manifest["records"])
        self.provenance = f"Recorded NVD responses captured {times[0]} through {times[-1]}"

    def close(self) -> None:
        """Stop the local server, if one was started."""
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)


class SyntheticSearchSource:
    """Serve fixed synthetic pages to the real keyword and CPE client."""

    def __init__(self) -> None:
        directory = Path(__file__).resolve().parent / "synthetic_search"
        self.manifest = json.loads((directory / "manifest.json").read_text())
        self.requests: Counter[str] = Counter()
        self.unexpected: list[str] = []
        responses = {}
        for entry in self.manifest["records"]:
            body = (directory / entry["file"]).read_bytes()
            if sha256(body).hexdigest() != entry["sha256"]:
                raise ValueError(f"Synthetic page digest mismatch: {entry['file']}")
            key = tuple(sorted((k, (v,)) for k, v in entry["parameters"].items()))
            responses[key] = (entry["id"], body)
        owner = self
        lock = Lock()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urlsplit(self.path)
                query = parse_qs(parsed.query, keep_blank_values=True)
                key = tuple(sorted((k, tuple(v)) for k, v in query.items()))
                if parsed.path != "/rest/json/cves/2.0" or key not in responses:
                    with lock:
                        owner.unexpected.append("Unexpected synthetic-page request")
                    self.send_error(404, "Request is outside the synthetic search scenario")
                    return
                request_id, body = responses[key]
                with lock:
                    owner.requests[request_id] += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args) -> None:
                """Keep routine transport logs out of notebook output."""

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}/rest/json/cves/2.0"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
