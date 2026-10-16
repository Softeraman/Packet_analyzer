"""Bounded HTTP adapter for the original native C++ analyzer. No upload retention."""
import ipaddress
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

ROOT = Path(__file__).resolve().parent.parent
ENGINE = os.environ.get('ANALYZER_BINARY', str(ROOT / 'web_analyzer'))
MAX_BYTES = 10 * 1024 * 1024
WORKERS = threading.BoundedSemaphore(2)

def validate_pcap(data):
    if len(data) < 24 or data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        raise ValueError('Use a classic .pcap file (microsecond timestamps). PCAPNG is not supported.')
    endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    _, major, minor, _, _, snaplen, network = struct.unpack(endian + 'IHHIIII', data[:24])
    if (major, minor) != (2, 4) or network != 1:
        raise ValueError('This demo supports PCAP 2.4 with Ethernet link type only.')
    offset, count = 24, 0
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError('Truncated packet header.')
        _, _, length, _ = struct.unpack_from(endian + 'IIII', data, offset)
        if length > min(snaplen, 65535) or offset + 16 + length > len(data):
            raise ValueError('Invalid or truncated packet data.')
        offset += 16 + length
        count += 1
        if count > 150000:
            raise ValueError('Please use a capture with at most 150,000 packets.')
    if not count:
        raise ValueError('The capture contains no packets.')

class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def log_message(self, *args):
        pass  # Do not log upload contents or filtering parameters.

    def reply(self, code, data, kind='application/json; charset=utf-8'):
        body = json.dumps(data).encode() if isinstance(data, dict) else data
        self.send_response(code)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ('/', '/index.html'):
            return self.reply(200, (ROOT / 'web/index.html').read_bytes(), 'text/html; charset=utf-8')
        if path == '/sample.pcap':
            return self.reply(200, (ROOT / 'test_dpi.pcap').read_bytes(), 'application/vnd.tcpdump.pcap')
        if path == '/health':
            return self.reply(200, {'status': 'ok', 'engine': 'native-cpp'})
        return self.reply(404, {'error': 'Not found'})

    def do_POST(self):
        parts = urlsplit(self.path)
        if parts.path != '/api/analyze':
            return self.reply(404, {'error': 'Not found'})
        if not WORKERS.acquire(blocking=False):
            return self.reply(429, {'error': 'The analyzer is busy. Please retry shortly.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 24 <= length <= MAX_BYTES:
                return self.reply(413, {'error': 'Choose a PCAP file between 24 bytes and 10 MB.'})
            query = parse_qs(parts.query)
            ip = query.get('ip', [''])[0].strip()
            app = query.get('app', [''])[0].strip()
            domain = query.get('domain', [''])[0].strip()
            if ip:
                ipaddress.IPv4Address(ip)
            if len(app) > 50 or len(domain) > 253:
                raise ValueError('The filter value is too long.')
            data = self.rfile.read(length)
            if len(data) != length:
                raise ValueError('Incomplete upload. Please try again.')
            validate_pcap(data)
            with tempfile.TemporaryDirectory(prefix='packet-demo-') as temp:
                capture, report = Path(temp) / 'capture.pcap', Path(temp) / 'report.json'
                capture.write_bytes(data)
                subprocess.run([ENGINE, str(capture), str(report), ip, app, domain],
                               check=True, timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                result = json.loads(report.read_text())
            return self.reply(200, result)
        except (ValueError, struct.error) as exc:
            return self.reply(400, {'error': str(exc)})
        except subprocess.TimeoutExpired:
            return self.reply(422, {'error': 'Capture analysis timed out. Try a smaller file.'})
        except (OSError, subprocess.CalledProcessError):
            return self.reply(500, {'error': 'The native analyzer could not process this capture.'})
        finally:
            WORKERS.release()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8081'))
    print(f'PacketScope listening on http://127.0.0.1:{port}', flush=True)
    ThreadingHTTPServer(('0.0.0.0', port), Handler).serve_forever()
