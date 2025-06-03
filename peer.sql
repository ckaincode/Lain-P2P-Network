-- (chunk, caminho) -> file_id, index
-- (file_id) -> mychunck%
-- (file_id, owners) -> chunck%,
-- (peer) -> pubkey

CREATE TABLE friends(
    username TEXT PRIMARY KEY NOT NULL,
    pkey TEXT NOT NULL
);

CREATE TABLE my_files(
    file_hash TEXT PRIMARY KEY NOT NULL,
    chunk_amt INTEGER NOT NULL,  -- Quantidade de Chunks
    curr_chunk_amt INTEGER NOT NULL
);


CREATE TABLE chunks(
    file_hash TEXT REFERENCES my_files(file_hash),
    chunk_idx INTEGER NOT NULL,
    chunk_hash TEXT NOT NULL,
    PRIMARY KEY  (file_hash,chunk_idx)
);
'''
--
--CREATE TABLE chunk_owners(
--    file_id TEXT NOT NULL,
--    chunk_owner TEXT NOT NULL,
--    chunk_amt INTEGER NOT NULL,
--    PRIMARY KEY (file_id, chunk_owner)
--);
'''
