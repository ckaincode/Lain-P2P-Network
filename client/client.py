import socket, hashlib, random, threading, base64, json, shutil, time, os
from common.utils import send_json, recv_json, hash_password, make_pkt, divide_in_chunks
from client.swarm import Swarm
from client.clientdb import PeerDB

TRACKER_HOST = 'localhost'
TRACKER_PORT = 5000
LISTENING_PORT = 0
download_start =  0
logged_user = None
logged_menu = False
swarm = None
active_sockets = {}
db = None
username_to_peer_id = {} 

def connect_to_tracker():
    return socket.create_connection((TRACKER_HOST, TRACKER_PORT))

def register():
    username = input("Usuário: ").strip()
    password = input("Senha: ").strip()
    hashed = hash_password(password)
    with connect_to_tracker() as sock:
        send_json(sock, {"action": "register", "username": username, "password": hashed})
        resp = recv_json(sock)
        print("✅ Registrado com sucesso!" if resp and resp.get("status") == "ok" else "Falha ao registrar.")

def login():
    global LISTENING_PORT
    if LISTENING_PORT == 0:
        print("[!] Aguardando inicialização do servidor local..."); time.sleep(1)
    username = input("Usuário: ").strip()
    password = input("Senha: ").strip()
    hashed = hash_password(password)
    with connect_to_tracker() as sock:
        send_json(sock, {"action": "login", "username": username, "password": hashed, "port": LISTENING_PORT})
        resp = recv_json(sock)
        if resp and resp.get("status") == "ok":
            print("Login bem-sucedido."); return username
        else:
            print("Login inválido."); return None

def announce_file(username, file_name, file_path):
    global swarm
    try:
        with open(file_path, 'rb') as f: content = f.read()
        size, file_hash = len(content), hashlib.sha256(content).hexdigest()
        chunk_count = divide_in_chunks(file_path, file_hash, username)
        
        with connect_to_tracker() as sock:
            send_json(sock, {"action": "announce_file", "username": username, "chunk_count": chunk_count, "file": {"name": file_name, "size": size, "hash": file_hash}})
            resp = recv_json(sock)
            if resp and resp.get("status") == "ok":
                print("Arquivo anunciado com sucesso.")
                if not db.entry_exists(file_hash):
                    db.create_or_reset_file_entry(username, file_hash, chunk_count)
                db.mark_file_as_complete(file_hash, chunk_count)
                swarm = Swarm(file_hash, db,chunk_count)
            else: print("Erro ao anunciar arquivo.")
    except Exception as e: print(f"Erro ao ler arquivo: {e}")

def start_heartbeat(username):
    while logged_user == username:
        try:
            with connect_to_tracker() as sock:
                send_json(sock, {"action": "heartbeat", "username": username}); recv_json(sock)
        except Exception: pass
        time.sleep(10)

def get_peers_with_files(file_hash):
    try:
        with connect_to_tracker() as sock:
            send_json(sock, {"action": "get_file", "hash": file_hash}); return recv_json(sock)
    except Exception as e: print(f"Falha na Pesquisa! {e}"); return None

def get_online_peers():
    try:
        with connect_to_tracker() as sckt:
            send_json(sckt, {"action": "get_online"}); print(recv_json(sckt))
    except Exception as e: print(f"Falha na busca: {e}")

def download_file(file_hash):
    global swarm
    if swarm and swarm.file_hash == file_hash and not db.has_all_chunks(file_hash):
        print("Download já em andamento."); return

    print(f"Iniciando download para o hash: {file_hash[:15]}...")
    file_info = get_peers_with_files(file_hash)
    if not file_info or file_info.get("status") != "ok" or not isinstance(file_info.get("peers"), list) or not file_info.get("peers"):
        print("[!] Nenhum peer encontrado ou erro ao contatar o tracker."); return

    peers_list = file_info["peers"]
    chunk_count = file_info["chunk_count"]

    if db.entry_exists(file_hash):
        # Valida se chunk_amt do banco bate com o tracker
        # Se não bater, recria a entrada (reset)
        local_chunk_amt = db.get_chunk_amt(file_hash)
        if local_chunk_amt != chunk_count:
            print("[!] chunk_amt divergente! Recriando entrada local...")
            db.create_or_reset_file_entry(logged_user, file_hash, chunk_count)
    else:
        db.create_or_reset_file_entry(logged_user, file_hash, chunk_count)

    swarm = Swarm(file_hash, db,chunk_count)
    try:
        with connect_to_tracker() as sckt:
            send_json(sckt, {"action": "join_swarm", "username": logged_user, "hash": file_hash, "announcer": False})
            res = recv_json(sckt)
            if not res or res.get('status') != 'ok':
                print("[!] Falha ao se registrar no swarm do tracker.")
                swarm = None
                return
    except Exception as e: print(f"[!] Erro ao entrar no swarm: {e}"); swarm = None; return
    
    print("Iniciando sessões com os peers...")
    for peer in peers_list:
        if peer["username"] == logged_user: continue
        try:
            if f"{peer['ip']}:{peer['port']}" in active_sockets:
                print(f"[!] Já conectado com {peer['username']}, pulando...")
                continue
            conn = socket.create_connection((peer['ip'], peer['port']), timeout=10)
            threading.Thread(target=handle_peer_session, args=(conn, (peer['ip'], peer['port'])), daemon=True).start()
        except Exception as e: print(f"[✘] Falha ao iniciar sessão com {peer['username']}: {e}")

def broadcast_have(file_hash, piece_index):
    message = {"action": "HAVE", "file_hash": file_hash, "index": piece_index}
    for peer_socket in list(active_sockets.values()):
        try: send_json(peer_socket, message)
        except Exception: pass

def handle_peer_session(conn, addr):
    peer_id = f"{addr[0]}:{addr[1]}"
    print(f"[+] Iniciando sessão com {peer_id}")
    active_sockets[peer_id] = conn
    
    try:
        send_json(conn, {"action": "HANDSHAKE", "username": logged_user})
    except Exception as e:
        print(f"[!] Falha no handshake/bitfield com {peer_id}: {e}")
        conn.close(); active_sockets.pop(peer_id, None); return

    last_request_time = 0
    try:
        conn.setblocking(False)
        while True:
       
            try:
                msg = recv_json(conn)
                if not msg: break
                
                action = msg.get("action")
                file_hash = msg.get("file_hash")

                if action == "HANDSHAKE":
                    peer_username = msg.get("username")
                    print(f"Handshake recebido: {peer_id} é {peer_username}")
                    username_to_peer_id[peer_username] = peer_id
                    # Adiciona ao swarm APÓS saber quem é o peer
                    if swarm:
                        my_bitmap = db.get_bitmap(swarm.file_hash)
                        send_json(conn, {"action": "BITFIELD", "file_hash": swarm.file_hash, "bitmap": my_bitmap})
                        swarm.add_peer(peer_id)

                elif action == "BITFIELD":
                    if swarm and file_hash == swarm.file_hash:
                        swarm.update_peer_bitmap(peer_id, msg.get("bitmap"))

                elif action == "CHUNK":
                    index = msg.get("piece_index")
                    payload_b64 = msg.get("payload")
                    payload_bytes = base64.b64decode(payload_b64)
                    checksum = hashlib.sha256(payload_bytes + index.to_bytes(4, byteorder='big')).hexdigest()
                    if checksum != msg.get("checksum"):
                        print(f"[!] Chunk {index} corrompido de {peer_id}, ignorado.")
                        continue
                    swarm.requested_chunks.pop(index, None)
                    #swarm.requested_chunks.discard(index)

                    try:
                        chunk_dir = os.path.join(logged_user, "files", file_hash)
                        os.makedirs(chunk_dir, exist_ok=True)
                        chunk_path = os.path.join(chunk_dir, f"{index}.json")
                        pkt_to_save = {
                            "action": "CHUNK", "file_hash": file_hash, "piece_index": index,
                            "checksum": checksum, "payload": payload_b64
                        }
                        with open(chunk_path, "w") as f:
                            json.dump(pkt_to_save, f)
                    except Exception as e:
                        print(f"[!] Erro ao salvar chunk {index} no disco: {e}")
                        continue 
                    
 
                    if db.mark_chunk_received(file_hash, index):
                    
                        if swarm:
                            swarm.record_chunk_received(peer_id, len(payload_bytes))
                        
                        print(f"[Downloader] Chunk {index} de {peer_id} salvo!")
                        broadcast_have(file_hash, index)


                    if db.has_all_chunks(file_hash):
                        if swarm and not swarm.is_reconstructing: #flag pra impedir dois arquivos
                            swarm.is_reconstructing = True
                            print(f"✅ Download completo! Reconstruindo o arquivo...")
                            output_path = os.path.join(f"downloads/{logged_user}", f"{file_hash}.bin")
                            reconstruct_file(logged_user, file_hash, output_path)

                elif action == "UNCHOKE":
                    if swarm: swarm.update_peer_choke_status(peer_id, is_choking=False)
                elif action == "CHOKE":
                    if swarm : swarm.update_peer_choke_status(peer_id, is_choking=True)
                elif action == "HAVE":
                    if swarm: swarm.mark_peer_have_chunk(peer_id, msg.get("index"))
                elif action == "PRIVATE_MESSAGE":
                    sender = msg.get("from_user")
                    recipient = msg.get("to_user")
                    text = msg.get("text")

                    if recipient == logged_user and db.is_friend(sender):
                        print(f"\n\n--- Nova Mensagem de {sender} ---")
                        print(f"> {text}")
                        print("---------------------------------")

                        try:

                            log_participants = sorted([logged_user, sender])
                            log_filename = f"{log_participants[0]}-{log_participants[1]}_chat.log"

                            os.makedirs("chat_logs", exist_ok=True)
                            log_path = os.path.join("chat_logs", log_filename)
                            

                            with open(log_path, "a") as log_file:
                                timestamp = time.strftime("%Y-%m-%d %H:%M:%S") # hora da mensagem
                                log_file.write(f"[{timestamp}] {sender}: {text}\n")

                        except Exception as e:
                            print(f"[!] Falha ao salvar a mensagem no log: {e}")
                        
                        print(f"\nUsuário: {logged_user}\n[1] Anunciar\n[2] Baixar\n[3] Online\n[4] Adicionar Amigo\n[5] Enviar Mensagem\n[9] Logout\n[0] Sair")
                        print(">> ", end="", flush=True)

                elif action == "GET_CHUNK":
                    index = msg.get("piece_index")
                    if not swarm or swarm.file_hash != file_hash or not swarm.can_upload_to(peer_id):
                        send_json(conn, {"status": "choked"})
                    else:
                        chunk_path = os.path.join(logged_user, "files", file_hash, f"{index}.json")
                        try:
                            with open(chunk_path, "r") as f: pkt = json.load(f)
                            send_json(conn, pkt)
                        except FileNotFoundError:
                            send_json(conn, {"status": "not_found"})
            except BlockingIOError: pass
            except Exception as e: print(f"[!] Erro na thread de leitura com {peer_id}: {e}"); break

            if swarm and swarm.file_hash:
                if not db.has_all_chunks(swarm.file_hash):
                    swarm.check_request_timeouts()

                    if not swarm.peer_states.get(peer_id, {}).get('peer_choking', True):
                        
                        # Usa a lógica RAREST FIRST para escolher a peça
                        piece_to_request = swarm.select_rarest_piece_to_request(peer_id)
                        
                        if piece_to_request is not None:
                            print(f"[{peer_id}] Solicitando chunk #{piece_to_request}...")
                            
                            # Adiciona ao dicionário de requisitados com timestamp
                            swarm.requested_chunks[piece_to_request] = (time.time(), peer_id)
                            
                            send_json(conn, {"action": "GET_CHUNK", "file_hash": swarm.file_hash, "piece_index": piece_to_request})
                            last_request_time = time.time()
            
                time.sleep(0.1)
    finally:
        print(f"[-] Encerrando sessão com {peer_id}.")
        disconnected_user = next((user for user, pid in username_to_peer_id.items() if pid == peer_id), None)
        if disconnected_user:
            del username_to_peer_id[disconnected_user]
            
        conn.close()
        if peer_id in active_sockets: del active_sockets[peer_id]
        if swarm: swarm.remove_peer(peer_id)
        
def add_friend_ui():
    """Interface para adicionar um amigo."""
    friend_name = input("Digite o nome de usuário do amigo a ser adicionado: ").strip()
    if not friend_name:
        print("Nome de usuário não pode ser vazio.")
        return
    
    # Adiciona o amigo no banco de dados local.
    db.add_friend(friend_name)


def send_message_ui():
    # Interface para enviar uma mensagem direta que reutiliza conexões existentes.
    recipient = input("Digite o nome do amigo para quem quer enviar a mensagem: ").strip()
    message_text = input("Digite sua mensagem: ")

    peer_id = username_to_peer_id.get(recipient)
    target_socket = None

    if peer_id and peer_id in active_sockets:
        target_socket = active_sockets[peer_id]
    else:
        addr = get_address_for_user(recipient)
        if addr:
            try:
                conn = socket.create_connection(addr, timeout=5)
                # Inicia a thread de sessão para a nova conexão
                threading.Thread(target=handle_peer_session, args=(conn, addr), daemon=True).start()
                time.sleep(0.5) # Dá tempo para o handshake ocorrer
                peer_id = username_to_peer_id.get(recipient)
                if peer_id:
                    target_socket = active_sockets[peer_id]
            except Exception as e:
                print(f"Falha ao conectar com {recipient}: {e}")
        else:
            print(f"Não foi possível encontrar {recipient}. Ele pode estar offline.")

    if target_socket:
        message = {
            "action": "PRIVATE_MESSAGE", "from_user": logged_user,
            "to_user": recipient, "text": message_text
        }
        send_json(target_socket, message)
        print("Mensagem enviada com sucesso!")
    else:
        print("Falha ao enviar mensagem.")

def get_address_for_user(username):
    # requisição ao tracker
    try:
        with connect_to_tracker() as sock:
            send_json(sock, {"action": "get_peer_address", "username": username})
            response = recv_json(sock)
            if response and response.get("status") == "ok":
                return (response["ip"], response["port"])
    except Exception as e:
        print(f"[!] Falha ao buscar endereço para {username}: {e}")
    return None

def handle_requests_peers():
    global LISTENING_PORT
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("", 0)); _, LISTENING_PORT = server.getsockname()
    server.listen()
    print(f"[🔗] Servidor peer ouvindo na porta {LISTENING_PORT}...")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_peer_session, args=(conn, addr), daemon=True).start()

def list_available_files():
    print("\nBuscando lista de arquivos no tracker...")
    try:
        with connect_to_tracker() as sock:
            send_json(sock, {"action": "list_files"})
            response = recv_json(sock)
            
            if response and response.get("status") == "ok":
                files = response.get("files", [])
                if not files:
                    print("ℹ️ Nenhum arquivo disponível no tracker no momento.")
                    return

                print("\n--- Arquivos Disponíveis ---")
                print(f"{'Nome do Arquivo':<30} | {'Hash Completo':<64}")
                print("-" * 98)
                
                for f in files:
                    # Pega o nome e o hash diretamente
                    name = f.get('name', 'N/A')
                    file_hash = f.get('hash', '')
                    print(f"{name:<30} | {file_hash:<64}")
                    
                print("-" * 98)

            else:
                print("❌ Falha ao buscar a lista de arquivos.")
    except Exception as e:
        print(f"❌ Erro de conexão ao buscar arquivos: {e}")

# Aqui Acontece Choke e Unchoke
def upload_manager_loop():
    while True:
        time.sleep(10)
        try:
            if swarm and swarm.file_hash: swarm.manage_uploads(active_sockets)
        except Exception: pass

def logout_cl():
    global logged_user, logged_menu
    logged_user, logged_menu = None, False

def reconstruct_file(username, file_hash, output_path):
    chunk_dir = os.path.join(username, "files", file_hash)
    if not os.path.isdir(chunk_dir): return False
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    try:
       
        # base64, binário não deu certo no JSON
        chunk_files = sorted([f for f in os.listdir(chunk_dir) if f.endswith(".json")], key=lambda f: int(f.split(".")[0]))
        with open(output_path, "wb") as out_f:
            for fname in chunk_files:
                with open(os.path.join(chunk_dir, fname), "r") as f:
                    pkt = json.load(f)
                    out_f.write(base64.b64decode(pkt["payload"]))
        print(f"[✔] Arquivo reconstruído: {output_path}")
        return True
    except Exception as e:
        print(f"[✘] Erro ao reconstruir arquivo: {e}"); return False

def logged_thread():
    global db, swarm, logged_menu
    db = PeerDB(username=logged_user) # Usa o banco de dados padrão p2p_peer
    #swarm = Swarm(None, db, 0)
    threading.Thread(target=start_heartbeat, args=(logged_user,), daemon=True).start()
    threading.Thread(target=upload_manager_loop, daemon=True).start()   
    while logged_user:
        print(f"\nUsuário: {logged_user}\n[1] Anunciar\n[2] Baixar\n[3] Online\n[4] Adicionar Amigo\n[5] Mandar Mensagem\n[6] Listar Arquivos\n[9] Logout\n[0] Sair")
        op = input(">> ").strip()
        if op == "1":
            file_name = input("Nome: "); file_path = input("Caminho: ")
            threading.Thread(target=announce_file, args=(logged_user, file_name, file_path)).start()
        elif op == "2":
            hash_buscada = input("Hash: ").strip()
            threading.Thread(target=download_file, args=(hash_buscada,)).start()
        elif op == "3": get_online_peers()
        elif op == "4":
            add_friend_ui()
        elif op == "5":
            send_message_ui()
        elif op == "6": # <-- NOVA CONDIÇÃO
            list_available_files()
        elif op == "9": 
            logout_cl()
        elif op == "0": 
            logout_cl()
            break
    logged_menu = False

def main():
    global logged_user, logged_menu
    server_ready_event = threading.Event()
    print("=== Peer Cliente ==="); threading.Thread(target=handle_requests_peers, daemon=True).start()
    time.sleep(0.5) # Pausa para o servidor de escuta iniciar e definir a porta
    while True:
        if not logged_user:
            print("\n[1] Registrar\n[2] Login\n[0] Sair")
            op = input(">> ").strip()
            if op == "1": register()
            elif op == "2": logged_user = login()
            elif op == "0": break
        elif not logged_menu:
            logged_menu = True
            threading.Thread(target=logged_thread).start()
        time.sleep(0.2)

if __name__ == "__main__":
    main()