"""Collect bounded applicability observations from the actual packaged runtime.

This is evidence, not an approval or an assertion that installed libraries lack
vulnerable code. Run offline with the package mounted read-only at /review.
"""

import ast
import hashlib
import json
from pathlib import Path
import platform
import shutil
import ssl
import sysconfig
import xml.parsers.expat

from security.verify_unreachable import go_functions


def source_evidence(paths):
    files, imports, calls = {}, {}, {}
    for path in sorted(paths):
        data = path.read_bytes()
        files[str(path)] = hashlib.sha256(data).hexdigest()
        tree = ast.parse(data, filename=str(path))
        imported, called = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or '')
                imported.update((node.module or '') + '.' + alias.name for alias in node.names)
            elif isinstance(node, ast.Call):
                called.add(ast.unparse(node.func))
        imports[str(path)] = sorted(imported)
        calls[str(path)] = sorted(called)
    if not files:
        raise ValueError('Missing application source')
    return {'files': files, 'imports': imports, 'calls': calls}


def expat_controls():
    # CPython's reviewed PyUnknownEncodingHandler supports single-byte mappings
    # and sets convert=NULL. Exercise valid decoding and multibyte rejection.
    valid = xml.parsers.expat.ParserCreate(encoding='windows-1252')
    decoded = []
    valid.CharacterDataHandler = decoded.append
    valid.Parse(b'<a>\xe9</a>', True)
    rejected = {}
    for encoding in ('shift_jis', 'big5', 'gbk'):
        parser = xml.parsers.expat.ParserCreate(encoding=encoding)
        try:
            parser.Parse(b'<a>\x81</a>', True)
        except ValueError as error:
            rejected[encoding] = str(error) == 'multi-byte encodings are not supported'
        except xml.parsers.expat.ExpatError:
            # An arbitrary parse error is insufficient evidence of the binding
            # restriction: retain false rather than claiming this as a pass.
            rejected[encoding] = False
        else:
            rejected[encoding] = False
    return {'single_byte_control': decoded == ['\u00e9'], 'multibyte_rejected': rejected}


def collect():
    binary = Path('/usr/local/bin/qurl').read_bytes()
    functions = go_functions(binary)
    stdlib = Path(sysconfig.get_path('stdlib'))
    files = [stdlib / name for name in (
        'ssl.py', 'http/cookies.py', 'http/cookiejar.py', 'tarfile.py', 'zipfile/__main__.py',
    )]
    files += [Path('/etc/ssl/openssl.cnf')]
    configurations = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in files if path.is_file()}
    paths = list(Path('/app').glob('*.py')) + list(Path('/usr/local/bin').glob('*.py'))
    return {
        'schema': 1,
        'architecture': {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()],
        'scope': 'Observations only; source review and an explicit bounded decision remain required',
        'application': source_evidence(paths),
        'library_and_config_sha256': configurations,
        'commands': {name: shutil.which(name) for name in ('sqlite3', 'xmlwf', 'sh', 'bash', 'openssl')},
        'qurl': {
            'sha256': hashlib.sha256(binary).hexdigest(), 'function_count': len(functions),
            'html_functions': sorted(n for n in functions if 'golang.org/x/net/html' in n),
            'openpgp_functions': sorted(n for n in functions if 'golang.org/x/crypto/openpgp' in n),
        },
        'python_tls': {
            'openssl': ssl.OPENSSL_VERSION,
            'default_ciphers': sorted(c['name'] for c in ssl.create_default_context().get_ciphers()),
            'quic_api': sorted(n for n in dir(ssl) + dir(ssl.SSLContext) if 'quic' in n.lower()),
        },
        'expat': {'version': xml.parsers.expat.EXPAT_VERSION, **expat_controls()},
    }


if __name__ == '__main__':
    print(json.dumps(collect(), indent=2, sort_keys=True))
