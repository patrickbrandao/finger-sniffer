-- Limpeza do schema e índice do filtro src_ip de /packets (auditoria de 2026-11).
-- 179: connections.quic_dcid nunca foi escrita nem lida; o DCID vive em memória (correlação) e no registro
--      (http3.dcid_hex do record_json).
-- 177: o filtro src_ip de GET /api/v1/packets casa o destino nos pacotes de saída (dir = 1), além da origem nos
--      de entrada (stray_packets_src); o índice do destino evita varrer a tabela nesse lado do OR.

-- +goose Up
ALTER TABLE connections DROP COLUMN quic_dcid;
CREATE INDEX stray_packets_dst ON stray_packets (dst_ip, ts_ns);

-- +goose Down
DROP INDEX stray_packets_dst;
ALTER TABLE connections ADD COLUMN quic_dcid TEXT;
