"""A stand-in Supervisor for booting the add-on image locally (development only).

Answers just what the add-on asks for: its options (bashio::config) and the Core API's
/config (the installed HA version). Run it as the container `supervisor` at the real
Supervisor address on a network shaped like HA's, then boot the image through /init:

    docker network create --subnet 172.30.32.0/23 hassio-sim
    docker run -d --name supervisor --network hassio-sim --ip 172.30.32.2 \
        -v "$PWD/scripts:/stub:ro" python:3.13-alpine python -u /stub/supervisor_stub.py
    docker run -d --name sniff-addon --network hassio-sim --ip 172.30.32.10 \
        -e SUPERVISOR_TOKEN=test -v /tmp/sniff-data:/data sniff-test:local

Requests to the panel then have to come from 172.30.32.2 (e.g. `docker exec supervisor
python -c ...`), with `X-Ingress-Path: /api/hassio_ingress/<token>` like real ingress.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

OPTS = {"exposure": "local", "jobs": 1, "github_token": ""}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print("GET", self.path, flush=True)
        if self.path.startswith("/addons/self/options/config"):
            body = {"result": "ok", "data": OPTS}
        elif self.path.startswith("/core/api/config"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"version": "2026.11.0"}).encode())
            return
        else:
            body = {"result": "ok", "data": {}}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())


HTTPServer(("0.0.0.0", 80), H).serve_forever()  # noqa: S104 - inside its container
