#!/usr/bin/env python3
"""Source-safe OWNED test-only TLS 1.3 + OS loopback PCAP/TShark proof.

No normal browser profile, external URL, credential, persistent keylog or secret
artifact. In full mode requires tcpdump/TShark on an admitted isolated runner.
Dry-run exercises only an owned local TLS endpoint; it is NOT a PCAP pass.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)


def fixture(directory, capture):
    root = Path(directory)
    cert, key = root / 'cert.pem', root / 'server-private.pem'
    command('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-x509', '-days', '1',
            '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
            '-addext', 'subjectAltName=IP:127.0.0.1')
    os.chmod(key, 0o600)
    keylog = root / 'owned-test-only.keylog'
    keylog.touch(mode=0o600, exist_ok=False)
    if keylog.stat().st_mode & 0o077:
        raise RuntimeError('keylog is not private')

    marker = 'owned-synthetic-data-request-7f93c128'
    response_marker = 'owned-synthetic-data-response-c2098d1b'
    request = ('POST /owned-fixture HTTP/1.1\r\nHost: localhost\r\n'
               'Content-Type: text/plain\r\nConnection: close\r\n'
               f'Content-Length: {len(marker)}\r\n\r\n{marker}').encode()
    body = response_marker.encode()
    reply = (f'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n'
             f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode() + body

    srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv.minimum_version = ssl.TLSVersion.TLSv1_3
    srv.maximum_version = ssl.TLSVersion.TLSv1_3
    srv.load_cert_chain(str(cert), str(key))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(15)
    port = listener.getsockname()[1]
    errors, observed = [], []

    def responder():
        try:
            raw, _ = listener.accept()
            with raw, srv.wrap_socket(raw, server_side=True) as conn:
                conn.settimeout(10)
                received = b''
                while marker.encode() not in received:
                    part = conn.recv(4096)
                    if not part:
                        break
                    received += part
                observed.append(received)
                if received != request:
                    raise AssertionError('owned request bytes did not match')
                conn.sendall(reply)
        except Exception as exc:
            errors.append(str(exc))
        finally:
            listener.close()

    server = threading.Thread(target=responder, daemon=True)
    server.start()
    capture_proc = None
    capture_path = root / 'capture.pcap'
    try:
        if capture:
            # A separate packet vantage at the OS loopback interface. Do not
            # substitute user-space relayed/reconstructed packets for this.
            capture_proc = subprocess.Popen([
                'sudo', '-n', 'tcpdump', '-Z', 'root', '-i', 'lo', '-U', '-s', '0',
                '-w', str(capture_path), 'tcp', 'port', str(port),
            ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
               start_new_session=True)
            time.sleep(1.3)
            if capture_proc.poll() is not None:
                raise RuntimeError('tcpdump exited before test handshake')

        cli = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cli.check_hostname = False  # owned one-day self-signed fixture only
        cli.verify_mode = ssl.CERT_NONE
        cli.minimum_version = ssl.TLSVersion.TLSv1_3
        cli.maximum_version = ssl.TLSVersion.TLSv1_3
        cli.keylog_filename = str(keylog)
        if keylog.stat().st_mode & 0o077:
            raise RuntimeError('TLS hook widened secret file permissions')
        with socket.create_connection(('127.0.0.1', port), timeout=10) as raw:
            with cli.wrap_socket(raw, server_hostname='localhost') as tls:
                if tls.version() != 'TLSv1.3':
                    raise AssertionError('TLS 1.3 not negotiated')
                peer_der = tls.getpeercert(binary_form=True)
                tls.sendall(request)
                received = b''
                while True:
                    data = tls.recv(4096)
                    if not data:
                        break
                    received += data
        server.join(8)
        if server.is_alive() or errors or observed != [request] or received != reply:
            raise AssertionError(f'test endpoint mismatch / errors={errors!r}')
        cert_der = subprocess.run(['openssl', 'x509', '-in', str(cert), '-outform', 'DER'],
                                  check=True, capture_output=True).stdout
        if peer_der != cert_der:
            raise AssertionError('live peer certificate digest mismatch')
        keylines = keylog.read_text().splitlines()
        labels = {line.split(' ', 1)[0] for line in keylines}
        if not {'CLIENT_TRAFFIC_SECRET_0', 'SERVER_TRAFFIC_SECRET_0'} <= labels:
            raise AssertionError('required TEST-ONLY TLS secrets missing')
        result = {
            'schema': 'evidence-service.owned-nic-test/v1',
            'test_data_only': True,
            'tls': 'TLSv1.3',
            'certificate_sha256': hashlib.sha256(peer_der).hexdigest(),
            'request_sha256': hashlib.sha256(request).hexdigest(),
            'response_sha256': hashlib.sha256(reply).hexdigest(),
            'test_secret_record_count': len([line for line in keylines if line and not line.startswith('#')]),
            'genuine_nic_pcap': False,
            'tshark_authenticated_decryption': False,
        }
        if capture:
            if capture_proc.poll() is None:
                # Send SIGINT to the independent capture process group, not
                # just sudo's parent PID. tcpdump must flush its pcap writer.
                time.sleep(0.4)
                os.killpg(capture_proc.pid, signal.SIGINT)
            try:
                stdout, stderr = capture_proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                capture_proc.kill()
                capture_proc.communicate()
                raise RuntimeError('tcpdump shutdown timed out')
            pcap_bytes = capture_path.stat().st_size if capture_path.exists() else 0
            if capture_proc.returncode not in (0, -signal.SIGINT, 130) or pcap_bytes <= 24:
                # tcpdump status is diagnostic only; never print payloads or keys.
                diagnostic = (stderr or '').splitlines()[-5:]
                raise AssertionError(f'kernel capture failed: exit={capture_proc.returncode}, '
                                     f'bytes={pcap_bytes}, status={diagnostic!r}')
            frame_numbers = command('tshark', '-r', str(capture_path),
                                    '-T', 'fields', '-e', 'frame.number').stdout.splitlines()
            if len(frame_numbers) < 6:
                raise AssertionError(f'insufficient original captured frames: {len(frame_numbers)}')
            # Only a synthetic TLS session has its secrets made available here.
            # The original PCAP is left encrypted; no DSB or plaintext is written to it.
            tshark = command('tshark', '-r', str(capture_path),
                             '-o', 'tls.keylog_file:' + str(keylog),
                             '-q', '-z', 'follow,tls,ascii,0')
            stream = tshark.stdout
            if marker not in stream or response_marker not in stream:
                raise AssertionError('tshark did not recover both owned TLS application directions')
            no_keys_env = dict(os.environ)
            no_keys_env.pop('SSLKEYLOGFILE', None)
            no_keys = command('tshark', '-r', str(capture_path), '-q',
                              '-z', 'follow,tls,ascii,0', env=no_keys_env).stdout
            if marker in no_keys or response_marker in no_keys:
                raise AssertionError('non-key replay unexpectedly disclosed application plaintext')
            pcap = capture_path.read_bytes()
            if marker.encode() in pcap or response_marker.encode() in pcap:
                raise AssertionError('encrypted NIC PCAP accidentally contains plaintext')
            result.update({
                'genuine_nic_pcap': True,
                'tshark_authenticated_decryption': True,
                'capture_sha256': hashlib.sha256(pcap).hexdigest(),
                'capture_bytes': len(pcap),
                'original_frame_count': len(frame_numbers),
                'missing_key_negative': True,
            })
        print('OWNED_TLS_NIC_RECEIPT=' + json.dumps(result, sort_keys=True), flush=True)
    finally:
        if capture_proc is not None and capture_proc.poll() is None:
            os.killpg(capture_proc.pid, signal.SIGINT)
            try:
                capture_proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                capture_proc.kill()
                capture_proc.communicate()
        listener.close()
        server.join(2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full', action='store_true', help='require genuine NIC capture and TShark')
    args = parser.parse_args()
    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='owned-synthetic-tls-') as directory:
            if Path(directory).stat().st_mode & 0o077:
                raise RuntimeError('insecure temporary directory')
            fixture(directory, capture=args.full)
    finally:
        os.umask(old_umask)

if __name__ == '__main__':
    main()