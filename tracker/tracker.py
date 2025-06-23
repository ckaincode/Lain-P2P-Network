from socket import *
import threading
import json
import requests 
import time
from common.utils import recv_json, send_json, hash_password
from tracker.bd import TrackerDB

# HOST = 'localhost'
PORT = 5000

def threadedConn(conn, addr):
    print(f"Conexão recebida de {addr}")
    try:
        while True:
            msg = recv_json(conn)
            if not msg:
                break

            action = msg.get("action")
            if action == "register":
                username = msg["username"]
                password_hash = msg["password"]
                success = db.register_user(username, password_hash)
                send_json(conn, {"status": "ok" if success else "error"})

            elif action == "login":
                username = msg["username"]
                password_hash = msg["password"]
                client_ip,client_port = conn.getpeername()
                if db.authenticate_user(username, password_hash, client_ip,client_port):
                    send_json(conn, {"status": "ok"})
                else:
                    send_json(conn, {"status": "error", "message": "Login inválido"})

            elif action == "announce_file":
                username = msg["username"]
                file = msg["file"]
                file_id = db.register_file(file["name"], file["size"], file["hash"])
                if file_id:
                    db.link_file_to_user(file["hash"], username,True)
                    send_json(conn, {"status": "ok"})
                else:
                    send_json(conn, {"status": "error", "message": "Erro ao registrar arquivo"})

            elif action == "get_online":
                ativos = db.get_active_peers()
                if ativos:
                    send_json(conn, {"status": "ok", "active_peers": ativos})
                else:
                    send_json(conn, {"status" : "error", "message": "Sem Peers Online"})
                    
            elif action == "get_file":

                file_hash = msg["hash"]

                if not file_hash:
                    send_json(conn, {"status": "error", "message": "Hash não fornecido."})
                    return

                peers = db.get_active_peers_for_file(file_hash)

                if peers:
                    # Constrói a resposta com os peers ativos que têm o arquivo
                    peer_list = []
                    for username, ip, port in peers:
                        peer_list.append({
                            "username": username,
                            "ip": ip,
                            "port": port
                        })

                    send_json(conn, {
                        "status": "ok",
                        "peers": peer_list
                    })
                else:
                    send_json(conn, {
                        "status": "ok",
                        "peers": "Não há peers como esse arquivo!"
                    })


            elif action == "heartbeat":
                username = msg["username"]
                if username:
                    try:
                        db.handle_heartbeat(username)
                        send_json(conn, {"status": "ok"})
                    except Exception as e:
                        print(f"Erro no heartbeat de {username}: {e}")
                        send_json(conn, {"status": "error", "message": "Erro interno ao registrar heartbeat"})
                else:
                    send_json(conn, {"status": "error", "message": "Username não fornecido no heartbeat"})
            
            elif action == "join_swarm":
                username = msg["username"]
                hash = msg["hash"]
                announcer = msg["announcer"]
                if username:
                    try:
                        db.link_file_to_user(hash,username,announcer)
                        send_json(conn, {'status': "ok"})
                    except Exception as e:
                        print(f"Erro no registro de {username}: {e}")
                        send_json(conn, {"status": "error", "message": "Erro ao se juntar ao swarm"})
                else:
                    send_json(conn, {"status": "error", "message": "Username não fornecido para swarm"})

                    
            elif action == "logout":
                username = msg["username"]
                if username:
                    try:
                        db.logout_user(username)
                        send_json(conn, {"status": "ok", "message": "Logout efetuado com sucesso."})
                    except Exception as e:
                        print(f"Erro ao deslogar {username}: {e}")
                        send_json(conn, {"status": "error", "message": "Erro interno ao deslogar"})
                else:
                    send_json(conn, {"status": "error", "message": "Username não fornecido no logout"})

            else:
                send_json(conn, {"status": "error", "message": "Ação desconhecida"})
            
    except Exception as e:
        print(f"[!] Erro com {addr}: {e}")
    finally:
        conn.close()
        print(f"Conexão encerrada com {addr}")

def clean_loop():
    dblocal = TrackerDB(5432)
    while True:
        dblocal.cleanup_inactive_users()
        time.sleep(15)

def start_tracker():
    clean_thread = threading._start_new_thread(clean_loop,())
    print("Tracker Iniciado\n")
    server = socket(AF_INET, SOCK_STREAM)
    server.bind(('', PORT))
    server.listen()
    while True:
        conn, addr = server.accept()
        if conn:
            connThread = threading._start_new_thread(threadedConn,(conn,addr))
    


db = TrackerDB(5432) # Porta nativa do PostgreSQL
