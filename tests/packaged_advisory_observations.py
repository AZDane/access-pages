"""Bounded, offline installed-library probes; no credentials or remote services.

The host-side security/check_runtime_advisories.py enforces every result and
binds it to the immutable image. Library defects are not proof of app exploitation.
"""

import hashlib
import http.client
import imaplib
import io
import json
from pathlib import Path
import platform
import sys
from unittest.mock import Mock

CHUNK_INVALID = (b'+1', b'-1', b'0x1', b'1_0', b' 1')
LENGTH_INVALID = ('+5', '-5', '5_0', '5 0', '\xb2')


class MemorySocket:
    def __init__(self, data):
        self.stream = io.BytesIO(data)

    def makefile(self, *args, **kwargs):
        return self.stream


def chunk_rejected(value, response_class=http.client.HTTPResponse):
    response = response_class(MemorySocket(
        b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
        + value + b'\r\nA\r\n0\r\n\r\n'))
    try:
        response.begin()
        # Exercise the framing parser directly, including negative sizes, without
        # asking read() to allocate or consume an attacker-specified body length.
        response._read_next_chunk_size()
        return False
    except ValueError:
        return True
    finally:
        response.close()


def content_length(value, response_class=http.client.HTTPResponse):
    response = response_class(MemorySocket(
        b'HTTP/1.1 200 OK\r\nContent-Length: ' + value.encode('latin1')
        + b'\r\n\r\nHello'))
    try:
        response.begin()
        return response.length
    finally:
        response.close()


def valid_chunk(response_class=http.client.HTTPResponse):
    response = response_class(MemorySocket(
        b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
        b'1;test=yes\r\nA\r\n0\r\n\r\n'))
    try:
        response.begin()
        return response.read() == b'A'
    finally:
        response.close()


def starttls_observation(buffered):
    client = imaplib.IMAP4.__new__(imaplib.IMAP4)
    client._tls_established = False
    client.capabilities = ('STARTTLS',)
    client.host = 'example.invalid'
    client._imaplib_file = None
    client._file = Mock()
    client.file = Mock()
    client.sock = Mock()
    client._readbuf = [b'before-tls\r\n'] if buffered else []
    client.untagged_responses = {}
    client._simple_command = Mock(return_value=('OK', [b'proceed']))
    observed = []
    client._get_capabilities = lambda: observed.append(client.readline())
    context = Mock()
    # Even a broken/unexpected reader is bounded by the host's execution timeout.
    context.wrap_socket.return_value.recv.side_effect = [b'after-tls\r\n', b'']
    try:
        client.starttls(context)
    except imaplib.IMAP4.abort:
        # The official fix rejects buffered plaintext before wrapping the socket.
        return buffered and not observed and not context.wrap_socket.called
    return observed == [b'after-tls\r\n']


def collect():
    checks = {
        'http.valid_chunk_extension': valid_chunk(),
        'http.valid_content_length': content_length('5') == 5,
        'http.valid_content_length_whitespace': content_length('5 \t') == 5,
        'imap.valid_post_tls_read': starttls_observation(False),
        'imap.discards_pre_tls_buffer': starttls_observation(True),
    }
    checks.update({f'http.reject_chunk.{value.decode()}': chunk_rejected(value)
                   for value in CHUNK_INVALID})
    checks.update({f'http.ignore_length.{value}': content_length(value) is None
                   for value in LENGTH_INVALID})
    return {
        'schema': 1, 'python': sys.version, 'machine': platform.machine(),
        'library_sha256': {m.__name__: hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest()
                           for m in (http.client, imaplib)},
        'checks': checks,
        'scope': 'Installed-library behavior, not an end-to-end application exploit or waiver',
    }


if __name__ == '__main__':
    print(json.dumps(collect(), indent=2, sort_keys=True))
