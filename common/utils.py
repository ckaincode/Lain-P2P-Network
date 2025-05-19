import hashlib
import json
import struct

def hash_password(password: str) -> str:
    """Retorna o hash SHA256 da senha em hexadecimal."""
    return hashlib.sha256(password.encode()).hexdigest()

def send_json(conn, data: dict):
    """Envia um objeto JSON com tamanho prefixado (4 bytes)."""
    raw = json.dumps(data).encode()
    length = struct.pack("!I", len(raw))
    conn.sendall(length + raw)

def recv_json(conn) -> dict:
    """Recebe um objeto JSON com prefixo de 4 bytes indicando o tamanho."""
    length_bytes = recvall(conn, 4)
    if not length_bytes:
        return None
    length = struct.unpack("!I", length_bytes)[0]
    data = recvall(conn, length)
    if not data:
        return None
    return json.loads(data.decode())

def recvall(conn, n):
    """Lê exatamente n bytes do socket."""
    data = b''
    while len(data) < n:
        part = conn.recv(n - len(data))
        if not part:
            return None
        data += part
    return data
