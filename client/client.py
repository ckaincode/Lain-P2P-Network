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

TRACKER_HOST = 'localhost'
TRACKER_PORT = 5000
MAX_CONN = 4
LISTENING_PORT = 0

logged_user = None
logged_menu = False
data_lock = threading.Lock()
swarm = None
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
    global LISTENING_PORT
    if LISTENING_PORT == 0:
        print("[!] Cliente ainda não está escutando. Aguarde e tente novamente.")
        return None
    username = input("Usuário: ").strip()
    password = input("Senha: ").strip()
    hashed = hash_password(password)

    with connect_to_tracker() as sock:
        send_json(sock, {
            "action": "login",
            "username": username,
            "password": hashed,
            "port": LISTENING_PORT
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

        chunk_count = divide_in_chunks(file_path,file_hash,username)
        with connect_to_tracker() as sock:
            send_json(sock, {
                "action": "announce_file",
                "username": username,
                "chunk_count": chunk_count,
                "file": {
                    "name": file_name,
                    "size": size,
                    "hash": file_hash
                }
            })

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
'''
def download_file(hash):
    global swarm
    if swarm.file_hash == hash:
        print("Baixando")
    else:
        try:
            with connect_to_tracker() as sckt:
                send_json(sckt, {"action" : "join_swarm",
                                 "username": logged_user,
                                 "hash" : hash,
                                 "announcer": False})
                res = recv_json(sckt)
            if res['status'] == 'ok':
                swarm = Swarm(hash,db)
                if not os.path.isdir(f'files/{hash}'):
                    os.mkdir(f'files/{hash}')
        except Exception as e:
            print("Erro ao entrar no swarm!")
            return None

'''

# Em client.py

def download_file(file_hash): # O argumento 'hash' foi renomeado para 'file_hash' para clareza
    global swarm
    if swarm and swarm.file_hash == file_hash:
        print("Download já em andamento.")
        return

    print(f"Iniciando download para o hash: {file_hash}")
    
    # --- PASSO 1: Obter a lista de peers do tracker (LÓGICA FALTANTE) ---
    file_info = get_peers_with_files(file_hash)
    if not file_info or file_info.get("status") != "ok" or not isinstance(file_info.get("peers"), list) or not file_info.get("peers"):
        print("[!] Nenhum peer encontrado ou erro ao contatar o tracker.")
        if file_info and file_info.get("message"):
            print(f"    Motivo: {file_info['message']}")
        return

    peers_list = file_info["peers"]
    chunk_count = file_info["chunk_count"] # Captura o chunk_count

    print(f"Arquivo possui {chunk_count} chunks. Criando entrada local...")
    db.create_or_reset_file_entry(logged_user, file_hash, chunk_count) # ESSA LINHA É CRUCIAL


    # --- PASSO 2: Juntar-se ao swarm e preparar o ambiente local (LÓGICA EXISTENTE MELHORADA) ---
    try:
        with connect_to_tracker() as sckt:
            send_json(sckt, {"action": "join_swarm", "username": logged_user, "hash": file_hash, "announcer": False})
            res = recv_json(sckt)
            if res['status'] != 'ok':
                print("[!] Falha ao se registrar no swarm do tracker.")
                return
    except Exception as e:
        print(f"[!] Erro ao entrar no swarm: {e}")
        return
        
    swarm = Swarm(file_hash, db)
    user_dir = os.path.join(logged_user, "files", file_hash)
    if not os.path.isdir(user_dir):
        os.makedirs(user_dir)   
        
    # --- PASSO 3: Conectar-se ativamente a cada peer (LÓGICA FALTANTE) ---
    for peer in peers_list:
        if peer["username"] == logged_user:
            continue
            
        print(f"--> Iniciando sessão com o peer {peer['username']} em {peer['ip']}:{peer['port']}")
        # Inicia uma thread para cada peer para não bloquear o programa principal
        threading.Thread(target=manage_peer_session, 
                         args=(peer['ip'], peer['port'], file_hash), 
                         daemon=True).start()

def manage_peer_session(peer_ip, peer_port, file_hash):
    """
    Gerencia a conexão ativa com um peer para solicitar chunks.
    """ 
    peer_id = f"{peer_ip}:{peer_port}"
    try:
        conn = socket.create_connection((peer_ip, peer_port), timeout=10)
        with conn:
            print(f"[✔] Conectado com sucesso a {peer_id}")
            active_sockets[peer_id] = conn
            swarm.add_peer(peer_id)

            # --- LOOP DE DOWNLOAD ATIVO (LÓGICA ESSENCIAL) ---
            while not db.has_all_chunks(file_hash):
                # Estratégia de seleção de qual chunk pedir (aqui, a mais simples)
                my_bitmap = db.get_bitmap(file_hash)
                
                # Encontra o primeiro chunk que não temos
                piece_to_request = -1
                for i, has_piece in enumerate(my_bitmap):
                    if not has_piece:
                        piece_to_request = i
                        break
                
                if piece_to_request == -1:
                    print(f"[{peer_id}] Não há mais chunks a pedir. Aguardando conclusão.")
                    break

                # Pede o chunk para o peer
                print(f"[{peer_id}] Solicitando chunk {piece_to_request}...")
                send_json(conn, {
                    "action": "GET_CHUNK",
                    "file_hash": file_hash,
                    "piece_index": piece_to_request
                })

                # Aguarda um tempo antes de pedir o próximo para não sobrecarregar
                time.sleep(15) 
            
            print(f"Sessão de download com {peer_id} finalizada.")

    except (socket.timeout, ConnectionRefusedError):
        print(f"[✘] Falha ao conectar em {peer_id}. O peer pode estar offline ou inalcançável.")
    except Exception as e:
        print(f"[!] Erro na sessão com {peer_id}: {e}")
    finally:
        # Limpa o peer da sessão ativa
        if peer_id in active_sockets:
            del active_sockets[peer_id]
        if swarm:
            swarm.remove_peer(peer_id)

def handle_peer_connection(conn, addr):
    peer_id = f"{addr[0]}:{addr[1]}"
    print(f'connected to :{peer_id}')
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
                chunk_path = os.path.join(logged_user, "files", file_hash, f"{piece_index}.json")  
                try:
                    with open(chunk_path, "r") as f:
                        chunk_payload_as_string = f.read()
                        
                    # Recarrega o JSON para extrair o payload original e o checksum
                    pkt = json.loads(chunk_payload_as_string)

                    send_json(conn, {
                        "action": "CHUNK",
                        "file_hash": file_hash,
                        "piece_index": piece_index,
                        "checksum": pkt["checksum"],
                        "payload": pkt["payload"] # Envia o payload em base64
                    })
                    print(f"[Seeder] Chunk {piece_index} enviado com sucesso.")

                except FileNotFoundError:
                    print(f"[Seeder] ERRO: Chunk {piece_index} não encontrado em {chunk_path}")
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
                    path = os.path.join(logged_user, "files", file_hash, f"{piece_index}.json")
                    with open(path, "w") as f:
                        json.dump(pkt, f)

                    db.mark_chunk_received(file_hash, index)

                    chunk_size = len(payload)
                    swarm.record_chunk_received(peer_id, chunk_size)

                    # Verifica se todos os chunks foram recebidos
                    if db.has_all_chunks(file_hash):
                        print(f"[✓] Todos os chunks recebidos para {file_hash}. Reconstruindo...")

                        output_path = os.path.join("downloads", f"{file_hash}.reconstructed")
                        if not reconstruct_file(logged_user, file_hash, output_path):
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
    global LISTENING_PORT # Acessa a variável global
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Tenta vincular a uma porta e armazena o número
    server.bind(("", 0)) # 0 para o SO escolher uma porta livre
    _, LISTENING_PORT = server.getsockname()

    server.listen()
    print(f"[🔗] Servidor peer ouvindo por conexões na porta {LISTENING_PORT}...") # Informa a porta

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

def reconstruct_file(username, expected_hash: str, output_path: str) -> bool:

    chunk_dir = os.path.join(username, "files", expected_hash)

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
            print(f"[!] Diretório e chunks de {expected_hash} foram apagados.")
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
    threading.Thread(target=handle_requests_peers, daemon=True).start()
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
    global swarm
    db = PeerDB(username=logged_user,port=5432)
    swarm = Swarm(None,db)
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
                threading._start_new_thread(download_file,(hash_buscada,))
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