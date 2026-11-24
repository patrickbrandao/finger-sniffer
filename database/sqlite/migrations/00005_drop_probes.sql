-- Remove a tabela probes (ADR 0077 item 2, task 383): era escrita a cada evento e consulta DNS com probe e nenhuma
-- leitura a usava. Um probe existe enquanto houver conexão ou consulta DNS visível com o seu ID.
-- O Down recria tabela e índice como na 00001, vazios.

-- +goose Up
DROP INDEX probes_last_seen;
DROP TABLE probes;

-- +goose Down
CREATE TABLE probes (
    probe_id   TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
) STRICT;
CREATE INDEX probes_last_seen ON probes (last_seen);
