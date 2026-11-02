"""Loopback subscription endpoint; callbacks must supply freshly verified access."""
import hashlib
import hmac
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def client_token(secret, client):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError('subscription signing key must contain at least 32 bytes')
    if not client.sub_id or not client.uuid or not client.email:
        raise ValueError('complete client subscription identity required')
    message = json.dumps([client.email, client.uuid, client.sub_id], separators=(',', ':')).encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def subscription_server(port, secret, authorize, render):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError('subscription signing key must contain at least 32 bytes')
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError('invalid subscription port')
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Subscription URLs contain bearer credentials.

        def respond(self, status, body=b''):
            self.send_response(status)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            match = re.fullmatch(r'/sub/([0-9a-f]{64})', self.path)
            if match is None:
                self.respond(404)
                return
            try:
                clients = authorize()
                selected = None
                now = int(time.time() * 1000)
                for client in clients:
                    token = client_token(secret, client)
                    if hmac.compare_digest(token, match.group(1)):
                        if selected is not None:
                            raise ValueError('duplicate subscription identity')
                        selected = client
                if selected is None or not selected.authorized(now_ms=now, unreported_bridge_bytes=0):
                    self.respond(404)
                    return
                content = render(selected.email)
                if not isinstance(content, str) or not content:
                    raise ValueError('subscription content unavailable')
                body = content.encode('utf-8')
                if not selected.authorized(now_ms=int(time.time() * 1000), unreported_bridge_bytes=0):
                    self.respond(404)
                    return
            except Exception:
                self.respond(503)
                return
            self.respond(200, body)
    return ThreadingHTTPServer(('127.0.0.1', port), Handler)
