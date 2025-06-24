CREATE TABLE friends(
    username TEXT PRIMARY KEY,
    pkey TEXT NOT NULL
);

CREATE TABLE extern_chats(
    chat_name TEXT NOT NULL,
    adm_pkey TEXT NOT NULL,
    chat_id INTEGER NOT NULL,
    PRIMARY KEY (chat_name,chat_id)
);

CREATE TABLE my_chats(
    chat_name TEXT NOT NULL,
    chat_priv_key INTEGER NOT NULL,
    chat_id INTEGER NOT NULL
);

CREATE TABLE chat_member(
    member TEXT NOT NULL,
    chat_id INTEGER NOT NULL,
    member_key BYTEA NOT NULL,
    PRIMARY KEY (member, chat_id)
);

CREATE TABLE my_files(
    uowner TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    chunk_amt INTEGER NOT NULL,  -- Quantidade de Chunks total do Arquivo
    curr_chunk_amt INTEGER NOT NULL,
    chunk_bit_map BYTEA NOT NULL,
    PRIMARY KEY (uowner,file_hash)
);
