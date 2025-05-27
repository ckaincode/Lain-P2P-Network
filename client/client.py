import socket
import hashlib
import getch
import random
import threading
import time
from common.utils import send_json, recv_json, hash_password

TRACKER_HOST = 'localhost'
TRACKER_PORT = 5000

logged_user = None

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
            #heartbeat = threading._start_new_thread(start_heartbeat,(username,))
            return username
        else:
            print("Login inválido.")
            return None

def announce_file(username):
    file_name = input("Nome do arquivo: ").strip()
    file_path = input("Caminho: ").strip()

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
            resp = recv_json(sock)
            if resp["status"] == "ok":
                print("Arquivo anunciado com sucesso.")
            else:
                print("Erro ao anunciar arquivo.")

    except Exception as e:
        print(f"Erro ao ler arquivo: {e}")


def start_heartbeat(username):
    global logged_user
    while True:
        if logged_user == None:
            break
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

def get_peers_with_files():
    print("Hash do Arquivo: ")
    hash = input().strip()
    try:
        with connect_to_tracker() as sock:
            send_json(sock, {
                "action": "get_file",
                "hash": hash
            })
            ans = recv_json(sock)
            print(ans)
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
    except Exception as e:
        print(f"Falha na busca: {e}")

    
def logout_cl(username):
    global logged_user
    try:
        with connect_to_tracker() as sock:
            send_json(sock, {
                "action": "logout",
                "username": username
            })
            resp = recv_json(sock)
            if resp["status"] == "ok":
                print("Logout bem-sucedido.")
            else:
                print("Erro ao deslogar:", resp.get("message", "Erro desconhecido."))
    except Exception as e:
        print("Erro na conexão com o tracker:", e)
    finally:
        logged_user = None

def main():
    print("=== Peer Cliente ===")
    global logged_user 
    while True:
        if not logged_user:
            print("Escolha o Serviço:")
            print("\n[1] Registrar")
            print("[2] Login")
            print("[0] Sair")
            op = getch.getch()
            if op == "1":
                print("Registro:")
                register()
            elif op == "2":
                print("Login: ")
                logged_user = login()
            elif op == "0":
                break
        else:
            print(f"\nUsuário logado: {logged_user}")
            print("[1] Anunciar arquivo")
            print("[2] Buscar Arquivo")
            print("[3] Ver Usuários Online")
            print("[9] Logout")
            print("[0] Sair")
            op = getch.getch()
            if op == "1":
                announce_file(logged_user)
            if op == "2":
                get_peers_with_files()
            if op == "3":
                get_online_peers()
            elif op == "9":
                logout_cl(logged_user)
            elif op == "0":
                if logged_user:
                    logout_cl(logged_user)
                break

if __name__ == "__main__":
    main()