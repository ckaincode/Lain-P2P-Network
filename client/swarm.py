# Arquivo: client/swarm.py

import random
from common.utils import send_json

class Swarm:
    def __init__(self, file_hash, db_instance):
        self.file_hash = file_hash
        self.db = db_instance
        
        # Dicionários de estado gerenciados pelo Swarm
        self.peer_rates = {}      # 'ip:port': {'download_bytes': int}
        self.peer_states = {}     # 'ip:port': {'peer_choking': bool}
        self.uploaders = []       # Lista de 'ip:port' para quem estamos enviando
        
        print(f"Swarm para o arquivo {file_hash} foi criado.")

    def add_peer(self, address):
        """Adiciona um novo peer ao nosso monitoramento."""
        if address not in self.peer_rates:
            self.peer_rates[address] = {'download_bytes': 0}
            # Inicializa o estado com um bitmap vazio
            self.peer_states[address] = {'peer_choking': True, 'bitmap': []} 
            print(f"Peer {address} adicionado ao swarm.")

    # --- MÉTODO NOVO ---
    def can_upload_to(self, address):
        """Verifica se podemos fazer upload para este peer (se ele não está chokado por nós)."""
        return address in self.uploaders

    # --- MÉTODO NOVO ---
    def register_peer_bitmap(self, address, bitmap):
        """Armazena o bitmap de um peer."""
        if address in self.peer_states:
            self.peer_states[address]['bitmap'] = bitmap
            print(f"Bitmap do peer {address} registrado.")

    # --- MÉTODO NOVO ---
    def mark_peer_have_chunk(self, address, index):
        """Marca que um peer possui um novo chunk."""
        if address in self.peer_states:
            # Garante que o bitmap é grande o suficiente
            if len(self.peer_states[address]['bitmap']) <= index:
                # Preenche com False se necessário
                self.peer_states[address]['bitmap'].extend([False] * (index + 1 - len(self.peer_states[address]['bitmap'])))
            self.peer_states[address]['bitmap'][index] = True
            print(f"Peer {address} agora possui o chunk {index}.")
            
    def remove_peer(self, address):
        """Remove um peer do nosso monitoramento."""
        if address in self.peer_rates: del self.peer_rates[address]
        if address in self.peer_states: del self.peer_states[address]
        if address in self.uploaders: self.uploaders.remove(address)
        print(f"Peer {address} removido do swarm.")

    def record_chunk_received(self, address, chunk_size):
        """Registra que recebemos um chunk de um peer (para Tit-for-Tat)."""
        if address in self.peer_rates:
            self.peer_rates[address]['download_bytes'] += chunk_size

    def update_peer_choke_status(self, address, is_choking):
        """Atualiza o estado de choke de um peer (se ele nos deu choke/unchoke)."""
        if address in self.peer_states:
            self.peer_states[address]['peer_choking'] = is_choking

    def manage_uploads(self, active_sockets):
        """
        Executa a lógica de Tit-for-Tat e Optimistic Unchoke.
        Esta função é chamada periodicamente pelo cliente.
        """
        # Tit-for-Tat: Ordena os peers pela quantidade de bytes que recebemos deles
        sorted_peers = sorted(
            self.peer_rates.items(),
            key=lambda item: item[1]['download_bytes'],
            reverse=True
        )

        # Seleciona os 3 melhores + 1 aleatório
        top_contributors = {item[0] for item in sorted_peers[:3]}
        others = [item[0] for item in sorted_peers[3:]]
        if others:
            top_contributors.add(random.choice(others))
        new_uploaders = set(top_contributors)
        old_uploaders = set(self.uploaders)

        peers_to_unchoke = new_uploaders - old_uploaders
        peers_to_choke = old_uploaders - new_uploaders

        # Envia as mensagens usando os sockets que o cliente forneceu
        for address in peers_to_unchoke:
            if address in active_sockets:
                print("UNCHOKING")
                send_json(active_sockets[address], {"action": "UNCHOKE", "file_hash": self.file_hash})

        for address in peers_to_choke:
            if address in active_sockets:
                print("CHOKING")
                send_json(active_sockets[address], {"action": "CHOKE", "file_hash": self.file_hash})

        # Atualiza o estado interno e reseta os contadores
        self.uploaders = list(new_uploaders)
        for rates in self.peer_rates.values():
            rates['download_bytes'] = 0