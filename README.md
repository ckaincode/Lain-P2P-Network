# Lain-P2P-Network

Rede P2P de compartilhamento de arquivos baseado no protocolo BitTorrent.

## Requisitos

### PostgreSQL Linux\WSL

Para instalar o PostgreSQL, execute
```sh
apt install postgresql

```
### Bibliotecas Python
Em ambiente controlado, execute:

```
make setup
```

## Cliente

Execute, com o tracker rodando em outro processo ou remotamente:

```
make client
```

## Tracker

Execute:

```
make tracker
```

## Setup do BD

Para configurar o banco de dados local, crie-o com PostgreSQL, Observe os campos necessários e altere-os em `tracker/bd.py`. Sugestão:

```sh
sudo -u postgres createuser 'seu_usuario' --superuser
sudo -u postgres createdb 'nome_do_banco' -O 'seu_usuario'
psql -U 'seu_usuario' -d 'nome_do_banco' -f p2p.sql

```

Para o banco do Peer, observe os campos necessários e altere-os em `client/clientdb.py. Sugestão:

```sh
sudo -u postgres createuser 'seu_usuario' --superuser
sudo -u postgres createdb 'nome_do_banco' -O 'seu_usuario'
psql -U 'seu_usuario' -d 'nome_do_banco' -f peer.sql

```


*OBS*: Desenvolvido no WSL Ubuntu 22.0.1
