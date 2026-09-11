from __future__ import annotations
import json, os, socket
from typing import Any

def request(payload: dict[str, Any], socket_path: str | None = None, session_id: str | None = None, timeout: float = 10):
    socket_path = socket_path or os.environ.get('FADS_BROKER_SOCKET'); session_id = session_id or os.environ.get('FADS_SESSION_ID')
    if not socket_path or not session_id: raise RuntimeError('FADS_BROKER_SOCKET and FADS_SESSION_ID are required')
    raw = (json.dumps({'session': session_id, **payload}, separators=(',', ':')) + '\n').encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout); s.connect(socket_path); s.sendall(raw); data = b''
        while b'\n' not in data:
            chunk = s.recv(65536)
            if not chunk: break
            data += chunk
    if not data: raise RuntimeError('broker closed without response')
    return json.loads(data.split(b'\n',1)[0])
