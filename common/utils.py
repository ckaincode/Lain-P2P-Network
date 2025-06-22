import hashlib
import json
import struct
import base64
import os

CHUNK_SIZE = 32 * 1024 # 256Kb

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

def make_pkt(chunk: bytes, index: int, file_hash: str) -> dict:
    index_bytes = index.to_bytes(4, byteorder='big')  
    checksum = hashlib.sha256(chunk + index_bytes).hexdigest()
    packet_dict = {
        "action": "CHUNK",
        "file_hash": file_hash,
        "piece_index": index,
        "checksum": checksum,
        "payload": chunk  # deve ser bytes; serializar depois
    }
    return packet_dict


def divide_in_chunks(file_path: str, file_hash: str):
    """Divide o arquivo em chunks, cria pacotes e os salva em arquivos nomeados por índice."""
    # Certifique-se de que a pasta existe
    chunk_dir = os.path.join("files", file_hash)
    os.makedirs(chunk_dir, exist_ok=True)

    try:
        with open(file_path, "rb") as f:
            index = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break  # Fim do arquivo

                pkt = make_pkt(chunk, index, file_hash)
                pkt["payload"] = base64.b64encode(pkt["payload"]).decode()
                chunk_path = os.path.join(chunk_dir, str(index) + ".json")
                with open(chunk_path, "w") as chunk_file:
                    json.dump(pkt, chunk_file)

                index += 1

        print(f"✅ Arquivo dividido em {index} pedaços e salvo em {chunk_dir}")
        return index

    except Exception as e:
        print(f"❌ Erro ao dividir arquivo: {e}")
        return 0