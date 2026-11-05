#!/usr/bin/env python3
"""Owned test-only genuine OS loopback PCAP and TShark TLS 1.3 proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from owned_tls_fixture import exchange, REQUEST_MARKER, RESPONSE_MARKER


def command(*args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, check=True, **kwargs)


def capture_and_validate(root, full):
    root = Path(root)
    pcap_path = root / 'capture.pcap'
    capture = None

    def start_capture(port):
        nonlocal capture
        if not full:
            return
        capture = subprocess.Popen([
            'sudo', '-n', 'tcpdump', '-Z', 'root', '--immediate-mode',
            '-i', 'lo', '-U', '-s', '0', '-w', str(pcap_path),
            'tcp', 'port', str(port),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
           start_new_session=True)
        time.sleep(1.3)
        if capture.poll() is not None:
            raise RuntimeError('capture exited before the owned TLS handshake')

    try:
        receipt, keylog = exchange(root, start_capture)
        if full:
            if capture.poll() is None:
                time.sleep(2.0)
                os.killpg(capture.pid, signal.SIGINT)
            try:
                _, stderr = capture.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.communicate()
                raise RuntimeError('capture shutdown timeout')
            size = pcap_path.stat().st_size if pcap_path.exists() else 0
            if size <= 24 or capture.returncode not in (0, -signal.SIGINT, 130):
                raise AssertionError(f'NIC capture failed: exit={capture.returncode}, '
                                     f'bytes={size}, status={(stderr or "").splitlines()[-5:]!r}')
            frames = command('tshark', '-r', str(pcap_path),
                             '-T', 'fields', '-e', 'frame.number').stdout.splitlines()
            if len(frames) < 6:
                raise AssertionError(f'insufficient actual packets: {len(frames)}')
            # Real captured bytes are never modified or merged with a keylog/DSB.
            pcap = pcap_path.read_bytes()
            if REQUEST_MARKER.encode() in pcap or RESPONSE_MARKER.encode() in pcap:
                raise AssertionError('plaintext leaked into the supposedly encrypted PCAP')
            decrypted = command('tshark', '-r', str(pcap_path),
                                '-o', f'tls.keylog_file:{keylog}',
                                '-q', '-z', 'follow,tls,ascii,0').stdout
            if REQUEST_MARKER not in decrypted or RESPONSE_MARKER not in decrypted:
                raise AssertionError('TShark did not independently decode both TLS directions')
            no_keys_env = dict(os.environ)
            no_keys_env.pop('SSLKEYLOGFILE', None)
            without_keys = command('tshark', '-r', str(pcap_path),
                                   '-q', '-z', 'follow,tls,ascii,0', env=no_keys_env).stdout
            if REQUEST_MARKER in without_keys or RESPONSE_MARKER in without_keys:
                raise AssertionError('unkeyed replay unexpectedly exposed plaintext')
            receipt.update({
                'genuine_nic_pcap': True,
                'tshark_authenticated_decryption': True,
                'original_frame_count': len(frames),
                'capture_sha256': hashlib.sha256(pcap).hexdigest(),
                'capture_bytes': size,
                'missing_key_negative': True,
            })
        print('OWNED_TLS_NIC_RECEIPT=' + json.dumps(receipt, sort_keys=True), flush=True)
    finally:
        if capture is not None and capture.poll() is None:
            os.killpg(capture.pid, signal.SIGINT)
            try:
                capture.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.communicate()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full', action='store_true', help='require true OS PCAP and TShark')
    args = parser.parse_args()
    umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='owned-test-tls-') as root:
            if Path(root).stat().st_mode & 0o077:
                raise RuntimeError('insecure temporary evidence dir')
            capture_and_validate(root, args.full)
    finally:
        os.umask(umask)

if __name__ == '__main__':
    main()
