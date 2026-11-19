"""Offline observations for advisory review; not a vulnerability waiver.

Uses bounded in-memory HTTP input and a mocked TLS handshake. No network,
credentials, exploit server or external resources are used. Results distinguish
the installed library behavior from application exploitability.
"""

import hashlib
import http.client
import imaplib
import io
import json
from pathlib import Path
import platform
import shutil
import sys
from unittest.mock import Mock


class MemorySocket:
    def __init__(self, chunk_size):
        self.stream = io.BytesIO(
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
            + chunk_size + b'\r\nA\r\n0\r\n\r\n')

    def makefile(self, *args, **kwargs):
        return self.stream


def accepts_chunk_size(size):
    response = http.client.HTTPResponse(MemorySocket(size))
    try:
        response.begin()
        return response.read() == b'A'
    except (ValueError, http.client.HTTPException):
        return False
    finally:
        response.close()


assert accepts_chunk_size(b'1'), 'Valid control response must parse'

client = imaplib.IMAP4.__new__(imaplib.IMAP4)
client._tls_established = False
client.capabilities = ('STARTTLS',)
client.host = 'example.invalid'
client._imaplib_file = None
client._file = Mock()
client.file = Mock()
client.sock = Mock()
client._readbuf = [b'buffered-before-tls\r\n']
client.untagged_responses = {}
client._simple_command = Mock(return_value=('OK', [b'proceed']))
observed = []
client._get_capabilities = lambda: observed.append(client.readline())
tls_socket = Mock()
tls_socket.recv.return_value = b''
context = Mock()
context.wrap_socket.return_value = tls_socket
client.starttls(context)

print(json.dumps({
    'python': sys.version,
    'machine': platform.machine(),
    'library_sha256': {m.__name__: hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest()
                       for m in (http.client, imaplib)},
    'CVE-2026-103995': {
        'accepts_non_hex_plus_chunk_size': accepts_chunk_size(b'+1'),
        'accepts_non_hex_prefix_chunk_size': accepts_chunk_size(b'0x1'),
    },
    'CVE-2026-115559': {
        'pre_tls_bytes_consumed_after_mocked_handshake': observed == [b'buffered-before-tls\r\n'],
    },
    'tools': {name: shutil.which(name) for name in ('sqlite3', 'xmlwf', 'openssl')},
    'scope': 'Installed-library observations; not an end-to-end application exploit or approval',
}, indent=2, sort_keys=True))
