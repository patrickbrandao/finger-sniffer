-- Limites de entrada da API de vereditos (ADR 0073 item 3.1, task 371): balde de registros do ingest por chave da
-- 9002 (`key create --ingest-rate --ingest-burst`; nulas = padrão, 500/s e 2 048) e registros aceitos no ingest por
-- chave e dia (sem cota diária de registros).

-- +goose Up
ALTER TABLE api_keys ADD COLUMN ingest_rate INTEGER;
ALTER TABLE api_keys ADD COLUMN ingest_burst INTEGER;
ALTER TABLE key_usage_daily ADD COLUMN records INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE key_usage_daily DROP COLUMN records;
ALTER TABLE api_keys DROP COLUMN ingest_burst;
ALTER TABLE api_keys DROP COLUMN ingest_rate;
