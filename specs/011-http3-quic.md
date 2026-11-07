# 011 — HTTP/3 e QUIC (UDP 443)

Status: aprovada
Depende de: 005, 008

## Contexto
Navegadores reais usam h3 quando o servidor anuncia (Alt-Svc ou HTTPS RR). O MVP serve HTTP/3 funcional e analisa
o Initial.

## Requisitos
- RF-01: servidor QUIC/HTTP/3 com `quic-go` + `http3` em UDP 443, mesmo certificado.
- RF-02: análise do Initial a partir dos datagramas crus (lidos antes do quic-go por um `net.PacketConn` wrapper
  e também presentes na captura): versão, tamanhos e valores de DCID/SCID, token, comprimento,
  **parâmetros de transporte na ordem** (com valores), ClientHello interno (decifrado com as chaves Initial
  derivadas do DCID) e seus fingerprints (JA4 com prefixo `q`), coalescência de pacotes, tamanho do datagrama
  (padding a 1200).
- RF-03: por requisição h3: pseudo-cabeçalhos e campos na ordem, QPACK (representação), SETTINGS do h3.
- RF-04: controles de resposta compatíveis (status, size, delay_*, h=).
- RF-05: anúncio: `Alt-Svc` nas respostas h1/h2 (spec 005) e HTTPS RR no DNS (spec 007).

## Interfaces e contratos
- Evento `fs.v1.web.http3.connection`; campo `http3` do registro. Correlação no store por 4-tupla + DCID.

## Critérios de aceite
- [ ] `curl --http3-only https://<id>.dns-monitor.tmsoft.com.br/p/<id>/` funciona e o registro traz os parâmetros
      de transporte na ordem.
- [ ] Chrome, abrindo a página, passa a usar h3 (visto no registro) a partir da segunda requisição ou de imediato
      via HTTPS RR.
- [ ] JA4 `q...` bate com FoxIO `ja4` sobre o pcap do Initial.

## Fora de escopo
- 0-RTT do lado servidor, migração de conexão, datagramas QUIC.

## Decisões relacionadas
- specs/decisions/0001-decisoes-iniciais.md
- specs/decisions/0009-stack-go-estatico.md
