# Lain-P2P-Network

Rede P2P de compartilhamento de arquivos baseado no protocolo BitTorrent.

## Requisitos

Em ambiente controlado, rode:

```
make setup

```

## Cliente

Rode:

```
make client

```

## Tracker

Rode:

```
make tracker

```

## Banco de Dados

Para configurar o banco de dados local, crie-o com:

```
psql -U "seu_usuario" -d "nome_do_banco" -f p2p.sql

```

Altere os campos em `tracker/bd.py`
