-- Pedidos da CLI ao serviço em execução (spec 018 RF-10 e "Dados", ADR 0056 item 2): `forget` e `lists refresh`
-- gravam uma linha; o serviço lê as pendentes (done_at nulo) a cada 2 s, executa, grava `result` e `done_at`.
-- Concluídos são apagados depois de 24 h pelo expurgo de hora em hora (o `arg` do forget é dado pessoal, ADR 0052).

-- +goose Up
CREATE TABLE control_requests (
    id         INTEGER PRIMARY KEY,
    op         TEXT    NOT NULL CHECK (op IN ('forget', 'lists_refresh')),
    arg        TEXT,                               -- prefixo do forget ou nome da lista (nulo = todas)
    created_at INTEGER NOT NULL,
    done_at    INTEGER,
    result     TEXT                                -- JSON com o resultado, escrito pelo serviço
) STRICT;

-- +goose Down
DROP TABLE control_requests;
