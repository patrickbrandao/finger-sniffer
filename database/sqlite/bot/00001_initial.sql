-- Schema inicial do banco do bot (spec 018 "Dados", ADRs 0047, 0051 e 0052).
-- Banco em disco (FS_BOT_DB), WAL com synchronous=NORMAL; auto_vacuum=INCREMENTAL definido pelo bot antes da
-- primeira migration, num banco novo. Tempos em segundos Unix (UTC); `hour` = epoch/3600 e `day` = epoch/86400.
-- IPs em 16 bytes (IPv4 mapeado em IPv6), para que um prefixo vire um intervalo de BLOBs no `forget`.

-- +goose Up
-- Chaves de API emitidas pela CLI (ADR 0051 item 2): só o SHA-256 da chave e um prefixo para exibição.
CREATE TABLE api_keys (
    id              TEXT    PRIMARY KEY,           -- ULID
    name            TEXT    NOT NULL,
    key_sha256      BLOB    NOT NULL UNIQUE,
    prefix          TEXT    NOT NULL,
    domains         TEXT    NOT NULL,              -- JSON: ["example.com", "*.example.com"]
    rate_per_s      INTEGER,
    burst           INTEGER,
    daily_quota     INTEGER,
    mode            TEXT    NOT NULL CHECK (mode IN ('observe', 'block')),
    webhook_url     TEXT,
    webhook_secret  BLOB,
    webhook_classes TEXT,                          -- classes separadas por vírgula (padrão bot,suspect)
    created_at      INTEGER NOT NULL,
    revoked_at      INTEGER
) STRICT;

-- Uso diário por chave (cota da ADR 0051 item 4; guardado 90 dias, ADR 0052 item 1).
CREATE TABLE key_usage_daily (
    key_id   TEXT    NOT NULL,
    day      INTEGER NOT NULL,
    requests INTEGER NOT NULL DEFAULT 0,
    limited  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, day)
) STRICT, WITHOUT ROWID;

-- Agregados por IP, site e hora (ADR 0052): 7 dias no máximo.
CREATE TABLE ip_hourly (
    ip             BLOB    NOT NULL,               -- 16 bytes
    site           TEXT    NOT NULL,
    hour           INTEGER NOT NULL,               -- epoch/3600
    requests       INTEGER NOT NULL DEFAULT 0,
    conns          INTEGER NOT NULL DEFAULT 0,
    reused         INTEGER NOT NULL DEFAULT 0,
    paths          INTEGER NOT NULL DEFAULT 0,
    statics        INTEGER NOT NULL DEFAULT 0,
    iv_n           INTEGER NOT NULL DEFAULT 0,
    iv_sum         REAL    NOT NULL DEFAULT 0,
    iv_sq_sum      REAL    NOT NULL DEFAULT 0,
    class_human    INTEGER NOT NULL DEFAULT 0,
    class_bot      INTEGER NOT NULL DEFAULT 0,
    class_suspect  INTEGER NOT NULL DEFAULT 0,
    class_good_bot INTEGER NOT NULL DEFAULT 0,
    class_unknown  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, site, hour)
) STRICT, WITHOUT ROWID;
CREATE INDEX ip_hourly_hour ON ip_hourly (hour);

-- Agregados por fingerprint e dia, sem IP.
CREATE TABLE fp_daily (
    kind        TEXT    NOT NULL CHECK (kind IN ('ja4', 'akamai', 'ja4h', 'ja4t')),
    value       TEXT    NOT NULL,
    day         INTEGER NOT NULL,                  -- epoch/86400
    ua_family   TEXT    NOT NULL,
    requests    INTEGER NOT NULL DEFAULT 0,
    ips         INTEGER NOT NULL DEFAULT 0,        -- aproximado
    class_bot   INTEGER NOT NULL DEFAULT 0,
    class_human INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (kind, value, day, ua_family)
) STRICT, WITHOUT ROWID;
CREATE INDEX fp_daily_day ON fp_daily (day);

-- Estado das listas de referência baixadas (ADR 0050).
CREATE TABLE lists (
    name       TEXT    PRIMARY KEY,
    url        TEXT,
    sha256     BLOB,
    entries    INTEGER,
    fetched_at INTEGER,
    ok_at      INTEGER,
    error      TEXT
) STRICT;

-- +goose Down
DROP TABLE lists;
DROP INDEX fp_daily_day;
DROP TABLE fp_daily;
DROP INDEX ip_hourly_hour;
DROP TABLE ip_hourly;
DROP TABLE key_usage_daily;
DROP TABLE api_keys;
