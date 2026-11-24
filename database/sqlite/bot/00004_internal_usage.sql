-- Uso das chaves na 9003 separado da cota da 9002 (ADR 0073 item 4, task 413): internal_requests é a parte de
-- requests feita pela 9003 (já somada em requests). A cota diária da 9002 é requests - internal_requests, igual em
-- memória e depois de um reinício. Linhas antigas ficam com 0 (o uso da 9003 de antes conta como da 9002).

-- +goose Up
ALTER TABLE key_usage_daily ADD COLUMN internal_requests INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE key_usage_daily DROP COLUMN internal_requests;
