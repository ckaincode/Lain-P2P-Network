import socket
import hashlib
import random
import threading
import base64
import json
import shutil
import time
import os
from common.utils import send_json, recv_json, hash_password, make_pkt, divide_in_chunks
from client.swarm import Swarm
from client.clientdb import PeerDB

TRACKER_HOST = '192.168.57.203'
TRACKER_PORT = 5000
MAX_CONN = 4

logged_user = None
logged_menu = False
data_lock = threading.Lock()
swarm = Swarm(None)
active_sockets = {}


def connect_to_tracker():
    return socket.create_connection((TRACKER_HOST, TRACKER_PORT))

def register():
    username = input("Usuário: ").strip()
    password = input("Senha: ").strip()
    hashed = hash_password(password)

    with connect_to_tracker() as sock:
        send_json(sock, {
            "action": "register",
            "username": username,
            "password": hashed
        })
        resp = recv_json(sock)
        if resp["status"] == "ok":
            print("✅ Registrado com sucesso!")
        else:
            print("Falha ao registrar (usuário pode já existir).")

def login():
    username = input("Usuário: ").strip()
    password = input("Senha: ").strip()
    hashed = hash_password(password)

    with connect_to_tracker() as sock:
        send_json(sock, {
            "action": "login",
            "username": username,
            "password": hashed
        })
        resp = recv_json(sock)
        if resp["status"] == "ok":
            print("Login bem-sucedido.")
            return username
        else:
            print("Login inválido.")
            return None

def announce_file(username,file_name,file_path):

    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        size = len(content)
        file_hash = hashlib.sha256(content).hexdigest() # hash SHA256

        with connect_to_tracker() as sock:
            send_json(sock, {
                "action": "announce_file",
                "username": username,
                "file": {
                    "name": file_name,
                    "size": size,
                    "hash": file_hash
                }
            })
            divide_in_chunks(file_path,file_hash)
            resp = recv_json(sock)
            if resp["status"] == "ok":
                print("Arquivo anunciado com sucesso.")
            else:
                print("Erro ao anunciar arquivo.")

    except Exception as e:
        print(f"Erro ao ler arquivo: {e}")


def start_heartbeat(username):
    print("Heartbeat Started")
    global logged_user
    while (logged_user != None):
        try:
            with connect_to_tracker() as sock:
                send_json(sock, {
                    "action": "heartbeat",
                    "username": username
                })
                recv_json(sock)  # apenas para manter o fluxo
        except Exception as e:
            print(f"[!] Falha no heartbeat: {e}")
        time.sleep(10)  # a cada 10 segundos

def get_peers_with_files(hash):
    try:
        with connect_to_tracker() as sock:
            send_json(sock, {
                "action": "get_file",
                "hash": hash
            })
            ans = recv_json(sock)
            print(ans)
            return ans
    except Exception as e:
        print(f"Falha na Pesquisa! {e}")

def get_online_peers():
    try:
        with connect_to_tracker() as sckt:
            send_json(sckt, {
                "action": "get_online"
            })
            res = recv_json(sckt)
            print(res)
            return res
    except Exception as e:
        print(f"Falha na busca: {e}")

def download_file(hash):
    if swarm.file_hash == hash:
        print("Baixando")
    else:
        try:
            with connect_to_tracker() as sckt:
                send_json(sckt, {"action" : "join_swarm",
                                 "hash" : hash,
                                 "announcer": False})
                res = recv_json(sckt)
        except Exception as e:
            print("Erro ao entrar no swarm!")
            return None
        if res['status'] == 'ok':
            swarm = Swarm(hash)
            if not os.path.isdir(f'files/{hash}'):
                os.mkdir(f'files/{hash}')

def handle_peer_connection(conn, addr):
    peer_id = f"{addr[0]}:{addr[1]}"
    active_sockets[peer_id] = conn
    swarm.add_peer(peer_id)  # opcional: se quiser adicionar aqui também
    try:
        while True:
            msg = recv_json(conn)
            if not msg:
                break

            action = msg.get("action")
            file_hash = msg.get("file_hash")

            if action == "GET_CHUNK":
                piece_index = msg.get("piece_index")


                if (swarm.file_hash != file_hash) or not swarm.can_upload_to(addr[0]):
                    send_json(conn, {"status": "choked"})
                    continue

                # lê chunk do disco
                chunk_path = f"files/{file_hash}/{piece_index}.json"
                try:
                    with open(chunk_path, "r") as f:
                        chunk_data = f.read()
                    send_json(conn, {
                        "action": "CHUNK",
                        "file_hash": file_hash,
                        "piece_index": piece_index,
                        "payload": chunk_data
                    })
                except FileNotFoundError:
                    send_json(conn, {"status": "not_found"})

            elif action == "CHUNK":
                index = msg.get("piece_index")
                payload = msg.get("payload")
                checksum = msg.get("checksum")
                file_hash = msg.get("file_hash")

                try:
                    payload = base64.b64decode(payload)
                    index_bytes = index.to_bytes(4, byteorder='big')
                    computed = hashlib.sha256(payload + index_bytes).hexdigest()

                    if computed != checksum:
                        print(f"[!] Chunk inválido - hash não confere! index {index}")
                        return

                    pkt = make_pkt(payload, index, file_hash)
                    path = f"files/{file_hash}/{index}.json"
                    with open(path, "w") as f:
                        json.dump(pkt, f)

                    db.mark_chunk_received(file_hash, index)

                    # Verifica se todos os chunks foram recebidos
                    if db.has_all_chunks(file_hash):
                        print(f"[✓] Todos os chunks recebidos para {file_hash}. Reconstruindo...")

                        output_path = os.path.join("downloads", f"{file_hash}.reconstructed")
                        if not reconstruct_file(file_hash, file_hash, output_path):
                            print("[✘] Arquivo corrompido. Reinicie o download.")
                        else:
                            print("[✔] Download finalizado com sucesso!")


                except Exception as e:
                    print(f"[!] Erro ao validar/salvar chunk: {e}")
           

            elif action == "MY_BITMAP":
                bitmap = msg.get("bitmap")
                if swarm.file_hash == file_hash:
                    swarm.register_peer_bitmap(addr[0], bitmap)

            elif action == "UNCHOKE":
                file_hash = msg.get("file_hash")
                if swarm.file_hash == file_hash:
                    # Informa ao swarm que o peer em 'addr' nos deu unchoke
                    swarm.update_peer_choke_status(addr, is_choking=False)
                else:
                    print(f"[!] UNCHOKE recebido para swarm desconhecido: {file_hash}")

            elif action == "CHOKE":
                file_hash = msg.get("file_hash")
                if swarm.file_hash == file_hash:
                    # Informa ao swarm que o peer em 'addr' nos deu choke
                    swarm.update_peer_choke_status(addr, is_choking=True)
                else:
                    print(f"[!] CHOKE recebido para swarm desconhecido: {file_hash}")

            elif action == "HAVE":
                file_hash = msg.get("file_hash")
                index = msg.get("index")
                if swarm.file_hash == file_hash:
                    swarm.mark_peer_have_chunk(addr[0], index)

            elif action in ("CHAT", "CHAT_ADMIN", "ADD_FRIEND"):
                # Placeholder
                send_json(conn, {"status": "not_implemented"})

            else:
                send_json(conn, {"status": "unknown_action"})

    except Exception as e:
        print(f"[!] Erro com peer {addr}: {e}")
    finally:
        conn.close()
        if peer_id in active_sockets:
            del active_sockets[peer_id]
        swarm.remove_peer(peer_id)


def handle_requests_peers():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("",6000))  # porta local do peer
    server.listen()
    print("[🔗] Servidor peer ouvindo por conexões...")

    while True:
        conn, addr = server.accept()
        print(f"[+] Conexão recebida de {addr}")
        threading.Thread(target=handle_peer_connection, args=(conn, addr), daemon=True).start()

def upload_manager_loop():
    while True:
        try:
            if swarm and swarm.file_hash:
                swarm.manage_uploads(active_sockets)
        except Exception as e:
            print(f"[!] Erro no gerenciador de uploads: {e}")
        time.sleep(10)  # Executa a cada 10 segundos

def logout_cl(username):

    global logged_menu
    global logged_user
    data_lock.acquire()
    logged_menu = False
    logged_user = None
    data_lock.release()

def reconstruct_file(file_hash: str, expected_hash: str, output_path: str) -> bool:
    chunk_dir = os.path.join("files", file_hash)

    if not os.path.isdir(chunk_dir):
        print(f"[!] Diretório não encontrado: {chunk_dir}")
        return False

    chunks = []
    
    try:
        files = sorted(os.listdir(chunk_dir), key=lambda f: int(f.split(".")[0]))

        for fname in files:
            if not fname.endswith(".json"):
                continue
            with open(os.path.join(chunk_dir, fname), "r") as f:
                pkt = json.load(f)
                payload_b64 = pkt["payload"]
                chunk_data = base64.b64decode(payload_b64)
                chunks.append(chunk_data)

        # Monta o arquivo
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "wb") as out_f:
            for chunk in chunks:
                out_f.write(chunk)

        # Verifica o hash
        with open(output_path, "rb") as final_file:
            final_data = final_file.read()
        computed_hash = hashlib.sha256(final_data).hexdigest()

        if computed_hash != expected_hash:
            print(f"[✘] Hash final inválido! Esperado: {expected_hash}, Obtido: {computed_hash}")
            os.remove(output_path)
            shutil.rmtree(chunk_dir, ignore_errors=True)
            print(f"[!] Diretório e chunks de {file_hash} foram apagados.")
            return False

        print(f"[✔] Arquivo reconstruído e verificado com sucesso: {output_path}")
        return True

    except Exception as e:
        print(f"[✘] Erro ao reconstruir/verificar arquivo: {e}")
        return False

def main():
    print("=== Peer Cliente ===")
    global logged_user
    global logged_menu 
    while True:
        if not logged_user:
            print("Escolha o Serviço:")
            print("\n[1] Registrar")
            print("[2] Login")
            print("[0] Sair")
            op = input().strip()
            if op == "1":
                print("Registro:")
                register()
            elif op == "2":
                print("Login: ")
                logged_user = login()
            elif op == "0":
                break
        elif not logged_menu:
            logged_menu = True
            threading._start_new_thread(logged_thread,())

def logged_thread():
    global logged_user
    global logged_menu
    global db
    db = PeerDB(5432,logged_user)
    heartbeat2 = threading._start_new_thread(start_heartbeat,(logged_user,))
    threading.Thread(target=upload_manager_loop, daemon=True).start()   
    while True:
        if(logged_user):
            print(f"\nUsuário logado: {logged_user}")
            print("[1] Anunciar arquivo")
            print("[2] Baixar Arquivo")
            print("[3] Ver Usuários Online")
            print("[9] Logout")
            print("[0] Sair")
            op = input().strip()
            if op == "1":
                file_name = input("Nome do arquivo: ").strip()
                file_path = input("Caminho: ").strip()
                threading._start_new_thread(announce_file,(logged_user,file_name,file_path))
            if op == "2":
                print("Hash do Arquivo: ")
                hash_buscada = input().strip()
                get_peers_with_files(hash_buscada)
            if op == "3":
                get_online_peers()
            elif op == "9":
                logout_cl(logged_user)
            elif op == "0":
                if logged_user:
                    logout_cl(logged_user)
                break

db = None

if __name__ == "__main__":
    main()