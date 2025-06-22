CREATE TABLE friends(
    username PRIMARY KEY TEXT NOT NULL,
    pkey TEXT NOT NULL
)

CREATE TABLE extern_chats(
    chat_name TEXT NOT NULL,
    adm_pkey TEXT NOT NULL,
    chat_id INTEGER NOT NULL,
    PRIMARY KEY (chat_name,chat_id)
);

CREATE TABLE my_chats(
    chat_name TEXT NOT NULL,
    chat_priv_key INTEGER NOT NULL,
    chat_id INTEGER NOT NULL,
);

CREATE TABLE chat_member(
    member TEXT NOT NULL,
    chat_id INTEGER NOT NULL,
    member_key BLOB NOT NULL,
    PRIMARY KEY (member, chat_id)
);

CREATE TABLE my_files(
    file_hash TEXT PRIMARY KEY NOT NULL,
    chunk_amt INTEGER NOT NULL,  -- Quantidade de Chunks total do Arquivo
    curr_chunk_amt INTEGER NOT NULL,
    chunk_bit_map BLOB NOT NULL
);
