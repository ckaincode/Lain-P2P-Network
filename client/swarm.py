# swarm.py - VERSÃO FINAL

import random
from common.utils import send_json

class Swarm:
    def __init__(self, file_hash, db_instance):
        self.file_hash = file_hash
        self.db = db_instance
        self.peer_rates = {}
        self.peer_states = {}
        self.uploaders = []
        
        # --- NOVOS ATRIBUTOS DE ESTADO ---
        self.requested_chunks = set() # Rastreia chunks que já pedimos
        self.is_reconstructing = False # Impede a reconstrução dupla

        if file_hash:
            print(f"Swarm para o arquivo {file_hash[:15]}... foi criado.")
        else:
            print("Swarm inicializado sem um arquivo ativo.")
    
    # ... (o resto da sua classe Swarm continua igual)
    def add_peer(self, address):
        if address not in self.peer_rates:
            self.peer_rates[address] = {'download_bytes': 0}
            self.peer_states[address] = {'peer_choking': True, 'bitmap': []}
            print(f"Peer {address} adicionado ao swarm.")

    def can_upload_to(self, address):
        return address in self.uploaders

    def mark_peer_have_chunk(self, peer_id, index):
        if peer_id in self.peer_states:
            peer_bitmap = self.peer_states[peer_id]['bitmap']
            if len(peer_bitmap) <= index:
                peer_bitmap.extend([False] * (index + 1 - len(peer_bitmap)))
            if not peer_bitmap[index]:
                peer_bitmap[index] = True

    def remove_peer(self, address):
        if address in self.peer_rates: del self.peer_rates[address]
        if address in self.peer_states: del self.peer_states[address]
        if address in self.uploaders: self.uploaders.remove(address)
        print(f"Peer {address} removido do swarm.")

    def record_chunk_received(self, address, chunk_size):
        if address in self.peer_rates:
            self.peer_rates[address]['download_bytes'] += chunk_size

    def update_peer_choke_status(self, address, is_choking):
        if address in self.peer_states:
            self.peer_states[address]['peer_choking'] = is_choking

    def manage_uploads(self, active_sockets):
        if not self.peer_rates: return
        sorted_peers = sorted(self.peer_rates.items(), key=lambda item: item[1]['download_bytes'], reverse=True)

        top_contributors = {item[0] for item in sorted_peers[:3]}
        others = [item[0] for item in sorted_peers[3:] if item[0] not in top_contributors]
        if others:
            top_contributors.add(random.choice(others))

        new_uploaders = set(top_contributors)
        old_uploaders = set(self.uploaders)
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

        self.uploaders = list(new_uploaders)
        for rates in self.peer_rates.values(): rates['download_bytes'] = 0