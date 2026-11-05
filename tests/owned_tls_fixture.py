"""Owned localhost TLS 1.3 endpoint. No external destinations or real credentials."""
import hashlib
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading

REQUEST_MARKER = 'owned-synthetic-data-request-7f93c128'
RESPONSE_MARKER = 'owned-synthetic-data-response-c2098d1b'


def exchange(root, before_connect):
    root = Path(root)
    cert, key, keylog = root / 'cert.pem', root / 'server-private.pem', root / 'owned-test-only.keylog'
    subprocess.run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-x509',
                    '-days', '1', '-keyout', str(key), '-out', str(cert),
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chmod(key, 0o600)
    keylog.touch(mode=0o600, exist_ok=False)
    if keylog.stat().st_mode & 0o077:
        raise RuntimeError('insecure test keylog')
    req_body, resp_body = REQUEST_MARKER.encode(), RESPONSE_MARKER.encode()
    request = (f'POST /owned-fixture HTTP/1.1\r\nHost: localhost\r\n'
               f'Content-Type: text/plain\r\nConnection: close\r\n'
               f'Content-Length: {len(req_body)}\r\n\r\n').encode() + req_body
    reply = (f'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n'
             f'Content-Length: {len(resp_body)}\r\nConnection: close\r\n\r\n').encode() + resp_body
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.minimum_version = server_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    server_ctx.load_cert_chain(str(cert), str(key))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(15)
    errors, observations = [], []

    def server():
        try:
            raw, _ = listener.accept()
            with raw, server_ctx.wrap_socket(raw, server_side=True) as tls:
                tls.settimeout(10)
                received = b''
                while req_body not in received:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    received += chunk
                observations.append(received)
                if received != request:
                    raise AssertionError('owned request did not match fixture bytes')
                tls.sendall(reply)
        except Exception as exc:
            errors.append(type(exc).__name__)
        finally:
            listener.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    try:
        before_connect(listener.getsockname()[1])
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.check_hostname = False  # synthetic self-signed local fixture ONLY
        client_ctx.verify_mode = ssl.CERT_NONE
        client_ctx.minimum_version = client_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        client_ctx.keylog_filename = str(keylog)
        if keylog.stat().st_mode & 0o077:
            raise RuntimeError('TLS hook widened test secret permissions')
        with socket.create_connection(('127.0.0.1', listener.getsockname()[1]), timeout=10) as raw:
            with client_ctx.wrap_socket(raw, server_hostname='localhost') as tls:
                if tls.version() != 'TLSv1.3':
                    raise AssertionError('TLS 1.3 not negotiated')
                peer_der = tls.getpeercert(binary_form=True)
                tls.sendall(request)
                data = b''
                while True:
                    fragment = tls.recv(4096)
                    if not fragment:
                        break
                    data += fragment
        thread.join(8)
        if thread.is_alive() or errors or observations != [request] or data != reply:
            raise AssertionError('owned TLS payload mismatch')
        cert_der = subprocess.run(['openssl', 'x509', '-in', str(cert), '-outform', 'DER'],
                                  capture_output=True, check=True).stdout
        if cert_der != peer_der:
            raise AssertionError('observed peer certificate differs from owned test certificate')
        lines = keylog.read_text().splitlines()
        labels = {line.split(' ', 1)[0] for line in lines}
        if not {'CLIENT_TRAFFIC_SECRET_0', 'SERVER_TRAFFIC_SECRET_0'} <= labels:
            raise AssertionError('required owned test secrets missing')
        return {
            'schema': 'evidence-service.owned-nic-test/v1',
            'test_data_only': True,
            'tls': 'TLSv1.3',
            'certificate_sha256': hashlib.sha256(peer_der).hexdigest(),
            'request_sha256': hashlib.sha256(request).hexdigest(),
            'response_sha256': hashlib.sha256(reply).hexdigest(),
            'test_secret_record_count': len([s for s in lines if s and not s.startswith('#')]),
            'genuine_nic_pcap': False,
            'tshark_authenticated_decryption': False,
        }, keylog
    finally:
        listener.close()
        thread.join(2)
