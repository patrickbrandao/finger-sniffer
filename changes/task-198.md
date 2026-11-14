- docs: `docs/api.md` no contrato 0.5.x com `ip.src_kind`, `tcp.syn_mss`, `tcp.mtu_implied` e `tcp.mss_reduction`;
  `docs/probes.md` (caso 11) lê os campos, traz a tabela de referência da ADR 0031 com a ressalva do clamping, a
  leitura certa de `tcp.segments_in` e o que cada `ip.src_kind` revela (task 198).
