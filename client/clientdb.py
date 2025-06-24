import psycopg2

class PeerDB:
    def __init__(self, username,dbname='p2p_peer', user='caiocesar', password='lokoloco10', host='localhost', port=5432):
        self.conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )
        self.conn.autocommit = True
        self.username = username
        self.cur = self.conn.cursor()

    def create_or_reset_file_entry(self, uowner, file_hash, chunk_amt):
        """Cria (ou reinicializa) entrada de arquivo com bitmap zerado."""
        empty_map = bytearray(chunk_amt)
        self.cur.execute("""
            INSERT INTO my_files (uowner, file_hash, chunk_amt, curr_chunk_amt, chunk_bit_map)
            VALUES (%s, %s, %s, 0, %s)
            ON CONFLICT (uowner, file_hash) DO UPDATE SET 
                chunk_amt = EXCLUDED.chunk_amt,
                curr_chunk_amt = 0,
                chunk_bit_map = EXCLUDED.chunk_bit_map
        """, (uowner, file_hash, chunk_amt, bytes(empty_map)))

    def get_bitmap(self, file_hash: str) -> list[bool]:
        self.cur.execute("""
            SELECT chunk_amt, chunk_bit_map
            FROM my_files
            WHERE uowner = %s AND file_hash = %s
        """, (self.username, file_hash))
        
        row = self.cur.fetchone()
        if not row:
            return []

        chunk_amt, bitmap_bytes = row
        bitmap_bits = []

        # Itera sobre o objeto bytes retornado pelo banco de dados
        for single_byte_object in bitmap_bytes:
            
            # --- CORREÇÃO DEFINITIVA ---
            # Extrai o valor inteiro (0-255) do objeto bytes de um byte.
            # Ex: se single_byte_object for b'\x0f', int_value será 15.
            int_value = single_byte_object[0]

            for i in range(8):
                # Agora a operação '>>' é feita entre dois inteiros.
                bit = (int_value >> (7 - i)) & 1
                bitmap_bits.append(bool(bit))

        return bitmap_bits[:chunk_amt]


    def mark_chunk_received(self, file_hash: str, index: int):
        self.cur.execute("""
            SELECT chunk_amt, curr_chunk_amt, chunk_bit_map
            FROM my_files
            WHERE uowner = %s AND file_hash = %s
        """, (self.username, file_hash))
        row = self.cur.fetchone()

        if not row:
            return False

        chunk_amt, curr_amt, bit_map = row
        byte_index = index // 8
        bit_index = index % 8

        mutable_bitmap = bytearray(bit_map)
        mutable_bitmap[byte_index] |= (1 << (7 - bit_index))  # Define bit como 1

        self.cur.execute("""
            UPDATE my_files
            SET chunk_bit_map = %s,
                curr_chunk_amt = curr_chunk_amt + 1
            WHERE uowner = %s AND file_hash = %s
        """, (bytes(mutable_bitmap), self.username, file_hash))
        self.conn.commit()
        return True

    def is_file_complete(self, uowner, file_hash):
        """Verifica se todos os chunks foram recebidos."""
        self.cur.execute("""
            SELECT chunk_amt, curr_chunk_amt FROM my_files
            WHERE uowner = %s AND file_hash = %s
        """, (uowner, file_hash))
        row = self.cur.fetchone()
        return row and row[0] == row[1]

    def remove_file_entry(self, uowner, file_hash):
        """Remove completamente a entrada de um arquivo (ex: hash inválido)."""
        self.cur.execute("""
            DELETE FROM my_files WHERE uowner = %s AND file_hash = %s
        """, (uowner, file_hash))

    def has_all_chunks(self, file_hash):
        self.cur.execute("""
            SELECT curr_chunk_amt, chunk_amt
            FROM my_files
            WHERE file_hash = %s AND uowner = %s
        """, (file_hash, self.username))
        row = self.cur.fetchone()
        if not row:
            return False
        curr, total = row
        return curr == total


    def close(self):
        self.cur.close()
        self.conn.close()
