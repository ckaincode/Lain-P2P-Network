import socket
import hashlib
import getch
import random
import threading
import time
import os
from common.utils import send_json, recv_json, hash_password, make_pkt, divide_in_chunks
from client.swarm import Swarm

TRACKER_HOST = '192.168.57.203'
TRACKER_PORT = 5000
MAX_CONN = 4

logged_user = None
logged_menu = False
data_lock = threading.Lock()
swarms = {}

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
    if swarms['hash']:
        print("Baixando")
    else:
        try:
            with connect_to_tracker() as sckt:
                send_json(sckt, {"action" : "join_swarm",
                                 "hash" : hash})
                res = recv_json(sckt)
        except Exception as e:
            print("Erro ao entrar no swarm!")
            return None
        if res['status'] == 'ok':
            swarms['hash'] = Swarm('hash')
            if not os.path.isdir(f'files/{hash}'):
                os.mkdir(f'files/{hash}')
            # TODO
            try:
                while(True):
                    pass
            except Exception as e:
                pass



def logout_cl(username):

    global logged_menu
    global logged_user
    data_lock.acquire()
    logged_menu = False
    logged_user = None
    data_lock.release()


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
    heartbeat2 = threading._start_new_thread(start_heartbeat,(logged_user,))    
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
                announce_file(logged_user)
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

if __name__ == "__main__":
    main()