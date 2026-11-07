-- Schema inicial do store (spec 004 "Dados", ADR 0005).
-- Tempos em nanossegundos desde a época Unix (UTC), inteiros.
-- O store abre o banco com PRAGMA foreign_keys=ON, journal_mode=WAL e auto_vacuum=INCREMENTAL
-- (este último definido antes da primeira migration, num banco novo).

-- +goose Up
CREATE TABLE probes (
    probe_id   TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
) STRICT;
CREATE INDEX probes_last_seen ON probes (last_seen);

CREATE TABLE connections (
    conn_id        TEXT PRIMARY KEY,
    probe_id       TEXT,
    l4             TEXT    NOT NULL CHECK (l4 IN ('tcp', 'udp')),
    family         INTEGER NOT NULL CHECK (family IN (4, 6)),
    src_ip         TEXT    NOT NULL,
    src_port       INTEGER NOT NULL,
    dst_ip         TEXT    NOT NULL,
    dst_port       INTEGER NOT NULL,
    quic_dcid      TEXT,
    proto          TEXT    NOT NULL,
    started_ns     INTEGER NOT NULL,
    ended_ns       INTEGER,
    degraded       INTEGER NOT NULL DEFAULT 0,
    pcap_truncated INTEGER NOT NULL DEFAULT 0,
    -- Registro completo (schema Connection do openapi.yaml), atualizado a cada evento.
    record_json    TEXT    NOT NULL,
    updated_ns     INTEGER NOT NULL
) STRICT;
CREATE INDEX connections_flow ON connections (l4, src_ip, src_port, dst_ip, dst_port, started_ns);
CREATE INDEX connections_probe ON connections (probe_id, started_ns);
CREATE INDEX connections_src ON connections (src_ip, started_ns);
CREATE INDEX connections_dst_port ON connections (dst_port, started_ns);
CREATE INDEX connections_started ON connections (started_ns);

-- Pacotes de uma conexão, até ela fechar e o pcap ser materializado.
CREATE TABLE packets (
    id       INTEGER PRIMARY KEY,
    conn_id  TEXT    NOT NULL REFERENCES connections (conn_id) ON DELETE CASCADE,
    ts_ns    INTEGER NOT NULL,
    dir      INTEGER NOT NULL CHECK (dir IN (0, 1)),
    wire_len INTEGER NOT NULL,
    frame    BLOB    NOT NULL
) STRICT;
CREATE INDEX packets_conn ON packets (conn_id, ts_ns);

-- pcap pronto (dois sentidos) de cada conexão.
CREATE TABLE pcaps (
    conn_id   TEXT PRIMARY KEY REFERENCES connections (conn_id) ON DELETE CASCADE,
    data      BLOB    NOT NULL,
    truncated INTEGER NOT NULL DEFAULT 0
) STRICT;

-- Eventos de aplicação recebidos (envelope + payload), na ordem de chegada.
CREATE TABLE app_events (
    id           INTEGER PRIMARY KEY,
    conn_id      TEXT    NOT NULL REFERENCES connections (conn_id) ON DELETE CASCADE,
    ts_ns        INTEGER NOT NULL,
    subject      TEXT    NOT NULL,
    payload_json TEXT    NOT NULL
) STRICT;
CREATE INDEX app_events_conn ON app_events (conn_id, ts_ns);

-- Bytes de aplicação de cada sentido, em pedaços com offset.
CREATE TABLE raw_streams (
    conn_id TEXT    NOT NULL REFERENCES connections (conn_id) ON DELETE CASCADE,
    dir     INTEGER NOT NULL CHECK (dir IN (0, 1)),
    offset  INTEGER NOT NULL,
    data    BLOB    NOT NULL,
    PRIMARY KEY (conn_id, dir, offset)
) STRICT;

CREATE TABLE dns_queries (
    id            INTEGER PRIMARY KEY,
    ts_ns         INTEGER NOT NULL,
    probe_id      TEXT,
    conn_id       TEXT,
    resolver_ip   TEXT    NOT NULL,
    resolver_port INTEGER NOT NULL,
    proto         TEXT    NOT NULL CHECK (proto IN ('udp', 'tcp')),
    qname         TEXT    NOT NULL,
    qtype         TEXT    NOT NULL,
    -- Registro completo (schema DNSQuery do openapi.yaml).
    record_json   TEXT    NOT NULL
) STRICT;
CREATE INDEX dns_queries_probe ON dns_queries (probe_id, ts_ns);
CREATE INDEX dns_queries_ts ON dns_queries (ts_ns);

-- Pacotes que não formam conexão (spec 004 RF-03).
CREATE TABLE stray_packets (
    id          INTEGER PRIMARY KEY,
    ts_ns       INTEGER NOT NULL,
    dir         INTEGER NOT NULL CHECK (dir IN (0, 1)),
    l4          TEXT    NOT NULL,
    src_ip      TEXT,
    dst_ip      TEXT,
    -- Registro completo (schema StrayPacket do openapi.yaml), sem o frame.
    record_json TEXT    NOT NULL,
    frame       BLOB    NOT NULL
) STRICT;
CREATE INDEX stray_packets_ts ON stray_packets (ts_ns);
CREATE INDEX stray_packets_src ON stray_packets (src_ip, ts_ns);

-- +goose Down
DROP TABLE stray_packets;
DROP TABLE dns_queries;
DROP TABLE raw_streams;
DROP TABLE app_events;
DROP TABLE pcaps;
DROP TABLE packets;
DROP TABLE connections;
DROP TABLE probes;
