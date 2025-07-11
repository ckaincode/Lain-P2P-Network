

import psycopg2

class PeerDB:
    def __init__(self, username, dbname='p2p_peer', user='caiocesar', password='lokoloco10', host='localhost', port=5432):
        try:
            # RECONFIGURAR DE ACORDO COM AMBIENTE LOCAL
            self.conn = psycopg2.connect(dbname=dbname, user=user, password=password, host=host, port=port)
            self.conn.autocommit = True
            self.username = username
            self.cur = self.conn.cursor()
        except psycopg2.OperationalError as e:
            print(f"ERRO CRÍTICO: Não foi possível conectar ao banco de dados '{dbname}'. Verifique se ele existe. Detalhes: {e}")
            exit()

    def entry_exists(self, file_hash: str) -> bool:
        if not file_hash: return False
        self.cur.execute("SELECT 1 FROM my_files WHERE uowner = %s AND file_hash = %s", (self.username, file_hash))
        return self.cur.fetchone() is not None

    def create_or_reset_file_entry(self, uowner, file_hash, chunk_amt):
        # Criação do BitMap
        num_bytes = (chunk_amt + 7) // 8 
        empty_map = bytearray(num_bytes)
        self.cur.execute(
            "INSERT INTO my_files (uowner, file_hash, chunk_amt, curr_chunk_amt, chunk_bit_map) VALUES (%s, %s, %s, 0, %s) "
            "ON CONFLICT (uowner, file_hash) DO UPDATE SET chunk_amt = EXCLUDED.chunk_amt, curr_chunk_amt = 0, chunk_bit_map = EXCLUDED.chunk_bit_map",
            (uowner, file_hash, chunk_amt, bytes(empty_map))
        )

    def get_bitmap(self, file_hash: str) -> list[bool]:
        if not file_hash: return []
        try:
            self.cur.execute("SELECT chunk_amt, chunk_bit_map FROM my_files WHERE uowner = %s AND file_hash = %s", (self.username, file_hash))
            if self.cur.rowcount == 0: return []
            row = self.cur.fetchone()
            if not row: return []

            chunk_amt, bitmap_bytes = row
            bitmap_bits = []
            iterable_bytes = [bitmap_bytes] if isinstance(bitmap_bytes, int) else bitmap_bytes or []

            for byte_value in iterable_bytes:
                int_value = byte_value[0] if isinstance(byte_value, bytes) else byte_value
                for i in range(8):
                    bit = (int_value >> (7 - i)) & 1
                    bitmap_bits.append(bool(bit))
            if len(bitmap_bits) < chunk_amt:
                print(f"[!] AVISO: bitmap tem {len(bitmap_bits)} bits, esperado {chunk_amt}. Completando com zeros.")
                bitmap_bits += [False] * (chunk_amt - len(bitmap_bits))
            return bitmap_bits[:chunk_amt]

        except psycopg2.Error as e:
            print(f"[DB_ERROR] em get_bitmap: {e}")
            return []



    def mark_chunk_received(self, file_hash: str, index: int):
        """Marca um chunk como recebido, definindo o bit correspondente como '1' de forma segura."""
        try:
            self.cur.execute(
                "SELECT chunk_bit_map FROM my_files WHERE uowner = %s AND file_hash = %s",
                (self.username, file_hash)
            )
            if self.cur.rowcount == 0:
                print(f"[DB_WARN] Nenhuma entrada encontrada para file_hash={file_hash}")
                return False

            row = self.cur.fetchone()
            if not row:
                print(f"[DB_WARN] fetchone() falhou para file_hash={file_hash}")
                return False

            bit_map = row[0]

            # Converte memoryview para bytes se necessário
            if isinstance(bit_map, memoryview):
                bit_map = bit_map.tobytes()

            # Garante que é um tipo suportado
            if not isinstance(bit_map, (bytes, bytearray)):
                print(f"[DB_ERROR] Tipo inesperado para bit_map: {type(bit_map)}")
                return False

            mutable_bitmap = bytearray(bit_map)
            byte_index, bit_index_from_left = divmod(index, 8)

            if byte_index >= len(mutable_bitmap):
                print(f"[DB_WARN] Índice de chunk {index} está fora dos limites do bitmap (len={len(mutable_bitmap)}).")
                return False

            # Checa se o bit já estava setado
            if (mutable_bitmap[byte_index] >> (7 - bit_index_from_left)) & 1:
                return True  # Já marcado, evita contagem duplicada

            # Marca o bit como recebido
            mask = 1 << (7 - bit_index_from_left)
            mutable_bitmap[byte_index] |= mask

            self.cur.execute(
                "UPDATE my_files SET chunk_bit_map = %s, curr_chunk_amt = curr_chunk_amt + 1 WHERE uowner = %s AND file_hash = %s",
                (bytes(mutable_bitmap), self.username, file_hash)
            )
            return True

        except psycopg2.Error as e:
            print(f"[DB_ERROR] em mark_chunk_received: {e}")
            return False
        except Exception as e:
            print(f"[EXCEPTION] em mark_chunk_received: {e}")
            return False

    def mark_file_as_complete(self, file_hash, chunk_amt):
        num_bytes = (chunk_amt + 7) // 8
        full_map = bytearray([0xFF] * num_bytes)
        self.cur.execute(
            "UPDATE my_files SET curr_chunk_amt = %s, chunk_bit_map = %s WHERE uowner = %s AND file_hash = %s",
            (chunk_amt, bytes(full_map), self.username, file_hash)
        )

    def has_all_chunks(self, file_hash: str) -> bool:
        if not file_hash: return False
        try:
            self.cur.execute("SELECT curr_chunk_amt, chunk_amt FROM my_files WHERE file_hash = %s AND uowner = %s", (file_hash, self.username))
            
            if self.cur.rowcount == 0: return False
            row = self.cur.fetchone()
            if not row: return False
            curr_raw, total_raw = row[0], row[1]
            curr = int.from_bytes(curr_raw, 'big') if isinstance(curr_raw, bytes) else curr_raw
            total = int.from_bytes(total_raw, 'big') if isinstance(total_raw, bytes) else total_raw
            
            return total > 0 and curr == total
            
        except psycopg2.Error as e:
            print(f"[DB_ERROR] em has_all_chunks: {e}")
            return False
        except (TypeError, ValueError) as e:
            print(f"[CONVERSION_ERROR] em has_all_chunks: {e}")
            return False

    # ... (resto da sua classe)

    def close(self):
        self.cur.close()
        self.conn.close()

    def add_friend(self, friend_username: str):
        """Adiciona um amigo à lista local. Ignora a chave pública por enquanto."""
        try:
            # pkey pra depois
            self.cur.execute(
                "INSERT INTO friends (username, pkey) VALUES (%s, %s) ON CONFLICT(username) DO NOTHING",
                (friend_username, 'none')
            )
            print(f"Usuário '{friend_username}' adicionado à sua lista de amigos.")
            return True
        except psycopg2.Error as e:
            print(f"[DB_ERROR] Falha ao adicionar amigo: {e}")
            return False

    def get_friends(self) -> list:
        """Retorna a lista de amigos."""
        self.cur.execute("SELECT username FROM friends")
        return [row[0] for row in self.cur.fetchall()]

    def is_friend(self, friend_username: str) -> bool:
        """Verifica se um nome de usuário existe na tabela de amigos."""
        self.cur.execute("SELECT 1 FROM friends WHERE username = %s", (friend_username,))
        return self.cur.fetchone() is not None
    
    def get_chunk_amt(self, file_hash):
        self.cur.execute("SELECT chunk_amt FROM my_files WHERE file_hash = %s AND uowner = %s", (file_hash, self.username))
        row = self.cur.fetchone()
        return row[0] if row else None
