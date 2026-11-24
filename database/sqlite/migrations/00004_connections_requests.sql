-- Contagem de requisições do registro em coluna própria (task 380): a lista resumida GET /api/v1/connections lê
-- requests daqui em vez de json_extract(record_json, '$.requests'), que decodificava o registro inteiro de cada
-- linha. O ingest grava o valor junto com record_json; as linhas anteriores são preenchidas uma vez aqui.
-- A coluna nova fica no fim da linha, depois de record_json: lida da tabela, ainda obrigaria o SQLite a percorrer
-- as páginas de transbordo do registro. Por isso connections_started passa a levar requests, e a lista sem filtro
-- (ORDER BY started_ns DESC) lê o valor do índice, com o mesmo custo para registros de 5 KB ou de 100 KB. conn_id
-- antes de requests mantém o desempate do mesmo started_ns na ordem de criação (ULID), como o rowid fazia.

-- +goose Up
ALTER TABLE connections ADD COLUMN requests INTEGER NOT NULL DEFAULT 0;
UPDATE connections SET requests = coalesce(json_extract(record_json, '$.requests'), 0);
DROP INDEX connections_started;
CREATE INDEX connections_started ON connections (started_ns, conn_id, requests);

-- +goose Down
DROP INDEX connections_started;
CREATE INDEX connections_started ON connections (started_ns);
ALTER TABLE connections DROP COLUMN requests;
