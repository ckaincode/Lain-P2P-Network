-- (chunk, caminho) -> file_id, index
-- (file_id) -> mychunck%
-- (file_id, owners) -> chunck%,
-- (peer) -> pubkey

CREATE TABLE friends(
    username TEXT PRIMARY KEY NOT NULL,
    pkey TEXT NOT NULL
);

CREATE TABLE my_files(
    file_id TEXT PRIMARY KEY NOT NULL,
    chunk_amt INTEGER NOT NULL  -- Quantidade de Chunks
);

CREATE TABLE chunks(
    chunk TEXT NOT NULL,
    caminho TEXT NOT NULL,
    file_id TEXT NOT NULL,
    chunk_idx INTEGER NOT NULL,
    PRIMARY KEY  (chunk, caminho)
);

CREATE TABLE chunk_owners(
    file_id TEXT NOT NULL,
    chunk_owner TEXT NOT NULL,
    chunk_amt INTEGER NOT NULL,
    PRIMARY KEY (file_id, chunk_owner)
);

