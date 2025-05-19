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

## Banco de Dados PostgreSQLs

Para configurar o banco de dados local, crie-o com PostgreSQL, Observe os campos necessários e altere-os em `tracker/bd.py`. Sugestão:

```sh
sudo -u postgres createuser 'seu_usuario' --superuser
sudo -u postgres createdb 'nome_do_banco' -O 'seu_usuario'
psql -U 'seu_usuario' -d 'nome_do_banco' -f p2p.sql
```

*OBS*: Desenvolvido no WSL Ubuntu 22.0.1
