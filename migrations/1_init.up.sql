CREATE TABLE users
(
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255)        NOT NULL,
    balance       INT         NOT NULL DEFAULT 1000 CHECK (balance >= 0),
    created_at    TIMESTAMP            DEFAULT NOW()
);

CREATE TABLE merch
(
    id    SERIAL PRIMARY KEY,
    name  VARCHAR(255) UNIQUE NOT NULL,
    price INT         NOT NULL CHECK (price > 0)
);

INSERT INTO merch (name, price)
VALUES ('t-shirt', 80),
       ('cup', 20),
       ('book', 50),
       ('pen', 10),
       ('powerbank', 200),
       ('hoody', 300),
       ('umbrella', 200),
       ('socks', 10),
       ('wallet', 50),
       ('pink-hoody', 500);

CREATE TABLE inventory
(
    id       SERIAL PRIMARY KEY,
    user_id  INT REFERENCES users (id) ON DELETE CASCADE,
    merch_id INT REFERENCES merch (id) ON DELETE SET NULL,
    quantity INT NOT NULL DEFAULT 1 CHECK (quantity >= 1),
    UNIQUE (user_id, merch_id)
);

CREATE INDEX idx_inventory_user_id ON inventory (user_id);
CREATE INDEX idx_inventory_merch_id ON inventory (merch_id);

CREATE TABLE transactions
(
    id          SERIAL PRIMARY KEY,
    sender_id   INT REFERENCES users (id) ON DELETE CASCADE,
    receiver_id INT REFERENCES users (id) ON DELETE CASCADE,
    amount      INT NOT NULL CHECK (amount > 0),
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_transactions_sender ON transactions (sender_id);
CREATE INDEX idx_transactions_receiver ON transactions (receiver_id);
CREATE INDEX idx_transactions_created_at ON transactions (created_at);
