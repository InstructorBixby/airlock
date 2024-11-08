"""Forward /v1/chat/completions upstream and record the request body.

Deliberately dumb for now. The point of this commit is to find out
whether every tool on this box will actually accept a different base
URL without complaining, before building anything on top of it.
"""
import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

UPSTREAM = "https://api.openai.com"
LOG = "calls.jsonl"


def record(path, body, status):
    with open(LOG, "a") as fh:
        fh.write(json.dumps({
            "ts": time.time(),
            "path": path,
            "status": status,
            "body": body,
        }) + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(n)
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {"__unparsed__": raw.decode("utf-8", "replace")}

        r = requests.post(
            UPSTREAM + self.path,
            data=raw,
            headers={
                "content-type": "application/json",
                "authorization": "Bearer " + os.environ.get(
                    "OPENAI_API_KEY", ""),
            },
            timeout=180,
        )
        record(self.path, body, r.status_code)

        payload = r.content
        self.send_response(r.status_code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8111)
    args = ap.parse_args()
    ThreadingHTTPServer(("127.0.0.1", args.port),
                        Handler).serve_forever()


if __name__ == "__main__":
    main()
