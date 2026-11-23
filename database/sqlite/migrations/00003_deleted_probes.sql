-- Probes apagados pelo DELETE cujas linhas ainda saem em lotes (ADR 0068, task 339).
-- conn_cut é o maior conn_id (ULID, ordenado pelo tempo) e dns_cut o maior id de dns_queries do probe no instante
-- do DELETE: as leituras excluem as linhas do probe até o corte enquanto a linha existir, e o laço de retenção
-- apaga essas linhas em lotes e tira a linha daqui no fim.

-- +goose Up
CREATE TABLE deleted_probes (
    probe_id   TEXT PRIMARY KEY,
    conn_cut   TEXT NOT NULL DEFAULT '',
    dns_cut    INTEGER NOT NULL DEFAULT 0,
    deleted_ns INTEGER NOT NULL
);

-- +goose Down
DROP TABLE deleted_probes;
