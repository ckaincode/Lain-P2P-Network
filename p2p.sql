
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    size BIGINT NOT NULL,
    hash TEXT UNIQUE NOT NULL
);

CREATE TABLE file_owners (
    file_id INTEGER REFERENCES files(id),
    username TEXT REFERENCES users(username),
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    PRIMARY KEY (file_id, username)
);

CREATE TABLE active_peers  (
    username TEXT PRIMARY KEY REFERENCES users(username),
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    last_seen TIMESTAMP NOT NULL
);


