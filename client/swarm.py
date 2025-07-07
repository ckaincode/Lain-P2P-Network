import threading
import time
import random
from common.utils import send_json

class Swarm:
    def __init__(self, file_hash, db_instance, chunk_count):
        self.file_hash = file_hash
        self.db = db_instance
        self.chunk_count = chunk_count
        
        # Estruturas de estado do Swarm
        self.peer_states = {}  # {'peer_id': {'bitmap': [...], 'is_choking': True}}
        self.peer_rates = {}   # {'peer_id': {'download_bytes': 0}}
        self.uploaders = set()
        
        # {piece_index: (timestamp, peer_id)}
        self.requested_chunks = {}

        self.piece_availability = [0] * self.chunk_count
        
        self.is_reconstructing = False
        self.lock = threading.Lock()
        print(f"▶️  Swarm para o arquivo {file_hash[:15]}... foi criado com {chunk_count} peças.")

    def add_peer(self, peer_id):
        with self.lock:
            if peer_id not in self.peer_states:
                self.peer_states[peer_id] = {'bitmap': [False] * self.chunk_count, 'peer_choking': True}
                self.peer_rates[peer_id] = {'download_bytes': 0}
                print(f"[Swarm] Peer {peer_id} adicionado.")

    def can_upload_to(self, address):
        """Verifica se estamos fazendo upload (unchoked) para um determinado peer."""
        return address in self.uploaders

    def remove_peer(self, peer_id):
        with self.lock:
            if peer_id in self.peer_states:
                # chokando um peer, tira seu bitmap da contagem de disponibilidade
                old_bitmap = self.peer_states[peer_id]['bitmap']
                for i, have in enumerate(old_bitmap):
                    if have:
                        self.piece_availability[i] -= 1
                del self.peer_states[peer_id]
            if peer_id in self.peer_rates:
                del self.peer_rates[peer_id]
            self.uploaders.discard(peer_id)
            self.requested_chunks = {i: (t, pid) for i, (t, pid) in self.requested_chunks.items() if pid != peer_id}
            print(f"[Swarm] Peer {peer_id} removido.")

    def update_peer_bitmap(self, peer_id, new_bitmap):
        with self.lock:
            if peer_id in self.peer_states:
                # Atualiza a contagem de disponibilidade
                old_bitmap = self.peer_states[peer_id]['bitmap']
                for i in range(self.chunk_count):
                    had_piece = old_bitmap[i]
                    has_piece = new_bitmap[i]
                    if has_piece and not had_piece:
                        self.piece_availability[i] += 1
                self.peer_states[peer_id]['bitmap'] = new_bitmap

    def mark_peer_have_chunk(self, peer_id, index):
        with self.lock:
            if peer_id in self.peer_states and not self.peer_states[peer_id]['bitmap'][index]:
                self.peer_states[peer_id]['bitmap'][index] = True
                self.piece_availability[index] += 1
                print(f"{peer_id} has {index}")
                
    def check_request_timeouts(self):
        TIMEOUT_SECONDS = 3
        with self.lock:
            now = time.time()
            timed_out_pieces = []
            for piece_index, (request_time, peer_id) in self.requested_chunks.items():
                if now - request_time > TIMEOUT_SECONDS:
                    print(f"⏰ TIMEOUT para a peça #{piece_index} do peer {peer_id}. Liberando...")
                    timed_out_pieces.append(piece_index)
            
            for piece_index in timed_out_pieces:
                del self.requested_chunks[piece_index]

    def record_chunk_received(self, peer_id, chunk_size):
 
        with self.lock:
            if peer_id in self.peer_rates:
                self.peer_rates[peer_id]['download_bytes'] += chunk_size

    def select_rarest_piece_to_request(self, peer_id):
        with self.lock:
            my_bitmap = self.db.get_bitmap(self.file_hash)
            needed_pieces = {i for i, have in enumerate(my_bitmap) if not have}
            
            available_to_request = needed_pieces - set(self.requested_chunks.keys())
            if not available_to_request: return None

            peer_bitmap = self.peer_states.get(peer_id, {}).get('bitmap', [])
            peer_has_pieces = {i for i in available_to_request if i < len(peer_bitmap) and peer_bitmap[i]}
            if not peer_has_pieces: return None

            # Encontra a peça mais rara que este peer possui
            rarity_map = {index: self.piece_availability[index] for index in peer_has_pieces}
            if not rarity_map: return None
            
            # Ordena as peças pela raridade (menor primeiro)
            sorted_by_rarity = sorted(rarity_map.keys(), key=lambda index: rarity_map[index])
            
            # Rarest First
            return sorted_by_rarity[0]

    
    def update_peer_choke_status(self, address, is_choking):
        with self.lock:
            if address in self.peer_states:
                self.peer_states[address]['peer_choking'] = is_choking

    def manage_uploads(self, active_sockets):
        with self.lock:
            if not self.peer_rates: return
            sorted_peers = sorted(self.peer_rates.items(), key=lambda item: item[1]['download_bytes'], reverse=True)

            top_contributors = {item[0] for item in sorted_peers[:4]}
            others = [item[0] for item in sorted_peers[4:] if item[0] not in top_contributors]
            if others:
                top_contributors.add(random.choice(others)) #opt unchoke

            new_uploaders = set(top_contributors)
            old_uploaders = self.uploaders
            peers_to_unchoke = new_uploaders - old_uploaders
            peers_to_choke = old_uploaders - new_uploaders

            for address in peers_to_unchoke:
                if address in active_sockets:
                    print(f"Enviando UNCHOKE para {address}")
                    send_json(active_sockets[address], {"action": "UNCHOKE", "file_hash": self.file_hash})

            for address in peers_to_choke:
                if address in active_sockets:
                    print(f"Enviando CHOKE para {address}")
                    send_json(active_sockets[address], {"action": "CHOKE", "file_hash": self.file_hash})

            self.uploaders = new_uploaders
            for rates in self.peer_rates.values(): rates['download_bytes'] = 0