import psycopg2 # Módulo de Interface com o DB
import time
import requests

"""
MUDAR DE ACORDO COM CONFIGURAÇÃO LOCAL

"""
DB_NAME = "p2p_tracker"
DB_USER = "caiocesar"
DB_PASSWORD = "lokoloco10"
DB_HOST = "localhost"


class TrackerDB:
    def __init__(self,porta):
        self.conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port= porta
        )
        self.conn.autocommit = True
        self.cur = self.conn.cursor()

    def register_user(self, username, password_hash):
        try:
            self.cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, password_hash)
            )
            return True
        except psycopg2.Error:
            return False

    def authenticate_user(self, username, password_hash,ip,port):
        self.cur.execute(
            "SELECT 1 FROM users WHERE username = %s AND password_hash = %s",
            (username, password_hash)
        )
        user = self.cur.fetchone()
        if user:
            self.cur.execute("""
                INSERT INTO active_peers (username, ip, port, last_seen)
                VALUES (%s,%s,%s, NOW())
                ON CONFLICT (username) DO UPDATE SET last_seen = NOW()
            """, (username,ip,port))
            self.conn.commit()
        return user is not None

    def register_file(self, name, size, file_hash,chunk_count):
        try:
            self.cur.execute(
                # Insere o chunk_count
                "INSERT INTO files (name, size, hash, chunk_count) VALUES (%s, %s, %s, %s) ON CONFLICT (hash) DO NOTHING RETURNING id",
                (name, size, file_hash, chunk_count)
            )
            row = self.cur.fetchone()
            if row:
                return row[0]
            else:
                # Já existia, buscar id
                self.cur.execute("SELECT id FROM files WHERE hash = %s", (file_hash,))
                row = self.cur.fetchone()
                return row[0] if row else None
        except psycopg2.Error as e:
            print("[DB ERROR]", e)
            return None
        
    def link_file_to_user(self, file_hash, username, announcer):
        try:
            # Pega o id do arquivo
            self.cur.execute("SELECT id FROM files WHERE hash = %s", (file_hash,))
            file_id = self.cur.fetchone()
            if not file_id:
                return False

            # Insere na tabela file_owners usando os ids corretos
            self.cur.execute(
                "INSERT INTO file_owners (file_id, username,announcer) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                (file_id,username,announcer)
            )
            self.conn.commit()
            return True
        except psycopg2.Error:
            return False
        
    def cleanup_inactive_users(self):
        try:
            print("Limpando...")
            self.cur.execute("DELETE FROM active_peers WHERE last_seen < NOW() - INTERVAL '20 seconds'")
            self.conn.commit()
            self.cur.execute("SELECT * FROM active_peers;")
            active = self.cur.fetchall()
            print(active)
        except Exception as e:
            pass
            # print(f"Erro ao limpar usuários inativos: {e}")

    # Não utilizada por enquanto
    def handle_heartbeat(self, username):
        self.cur.execute("""
          UPDATE active_peers
          SET last_seen = NOW()
          WHERE username = %s
        """, (username,))
        self.conn.commit()

    def logout_user(self, username):
        self.cur.execute("DELETE FROM active_peers WHERE username = %s", (username,))
        self.conn.commit()
    
    def get_active_peers(self):
        self.cur.execute("""
            SELECT ap.username, ap.ip, ap.port
            FROM active_peers ap
""" )
        return self.cur.fetchall()
    
    def get_active_peers_for_file(self, file_hash):
        # Esta query agora busca o chunk_count também
        self.cur.execute("""
            SELECT u.username, ap.ip, ap.port, f.chunk_count   
            FROM files f
            JOIN file_owners fo ON f.id = fo.file_id
            JOIN active_peers ap ON fo.username = ap.username
            JOIN users u ON u.username = fo.username
            WHERE f.hash = %s
        """, (file_hash,))      
        
        results = self.cur.fetchall()
        if not results:
            return None
            
        # Estrutura a resposta
        peers = [{"username": r[0], "ip": r[1], "port": r[2]} for r in results]
        chunk_count = results[0][3] # O chunk_count é o mesmo para todos os resultados
        
        return {"peers": peers, "chunk_count": chunk_count}

        
'''
    def get_active_peers_for_file(self, file_hash):
            self.cur.execute("""
                SELECT u.username, ap.ip, ap.port     
                FROM files f
                JOIN file_owners fo ON f.id = fo.file_id
                JOIN active_peers ap ON fo.username = ap.username
                JOIN users u ON u.username = fo.username
                WHERE f.hash = %s
            """, (file_hash,))      
            return self.cur.fetchall()
'''