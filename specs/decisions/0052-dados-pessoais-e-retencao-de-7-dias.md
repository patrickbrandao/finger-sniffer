# 0052 — Dados pessoais (LGPD) e retenção de 7 dias dos agregados

Status: provisória (revisar quando o humano responder às pendências P5–P7 da spec 018)
Data: 2026-11-16

## Contexto
Decisão do humano (entrevista, seção 3): retenção de agregados por IP/fingerprint de **7 dias**, com as conexões
cruas na retenção atual (10 min); o IP é dado pessoal e exige tratamento de LGPD na spec. Na seção 5 o humano aceitou
"por enquanto" expor pela API aberta o tráfego capturado dos sites atrás do traefik (ADR 0038 item 6), deixando LGPD
para esta fase.

## Decisão
1. **Dados tratados pelo bot e retenção**:
   | Dado | Onde | Retenção |
   | --- | --- | --- |
   | conexões e requisições (visão do store e do fork) | memória do bot | 10 min (`FS_BOT_CONN_TTL`) |
   | vereditos por requisição | memória do bot e feed/webhook | 10 min |
   | agregados por IP e site por hora (requisições, conexões, caminhos distintos, estáticos, intervalos, classes) | disco | 7 dias (`FS_BOT_AGG_RETENTION`, máximo 7 dias) |
   | agregados por fingerprint por dia (contagens por família de UA e classe, sem IP) | disco | 7 dias |
   | chaves, uso diário, webhooks | disco | enquanto a chave existir; uso diário 90 dias |
   | listas baixadas | disco | até a próxima atualização |
   Expurgo de hora em hora; nada com IP passa de 7 dias e 1 hora.
2. **Minimização**: o bot não guarda corpo, query string, valores de cookie, de `Authorization` nem de campos fora
   da lista permitida (ADR 0048 item 3); caminhos entram nos agregados só como contagem e hash (SHA-256 truncado com
   sal do dia, descartado com o dia); o log (journald) não leva IP fora de erro com prazo de 24 h (ADR 0012).
3. **Finalidade e base legal (provisória, pendência P5)**: segurança da informação e prevenção de abuso e fraude
   dos sites (LGPD art. 7º IX, legítimo interesse, com a minimização acima e o art. 10 §2 da transparência). Os
   agregados não servem a perfil de marketing nem são cedidos fora das chaves com domínio autorizado.
4. **Papéis**: para os sites do humano atrás do traefik do finger-01, o humano é controlador; para clientes externos,
   o cliente é controlador dos dados dos visitantes dele e o espelho é operador (pendência P6: identificação do
   controlador, encarregado e canal do titular).
5. **Direitos do titular**: `finger-sniffer-bot forget <ip|prefixo>` apaga agregados e vereditos em memória daquele
   IP ou prefixo; a página `htdocs/privacy.html` (inglês e português) descreve finalidade, dados, retenção e o canal
   de contato (texto e contato do humano, P6).
6. **API aberta do store e tráfego dos sites (provisória, pendência P7)**: proposta do architect — o store deixa de
   expor na API aberta (listagens, `connections/{id}`, pcap, raw, pacotes e feed global) as conexões cujo destino é
   porta do traefik (`FS_PRIVATE_PORTS`, padrão `80,443,8081` TCP e `443` UDP), que continuam indo ao bot por
   `fs.v1.store.connection`. Muda o comportamento da ADR 0007 e da ADR 0038 item 6; **só é implementada depois da
   resposta do humano** (nenhuma tarefa da primeira onda).

## Alternativas consideradas
- IP com hash em vez de claro — as consultas por IP (`/bot/v1/ip/{ip}`) e a verificação de robô precisam do IP;
  hash sem sal é reversível para IPv4 e com sal rotativo quebra a janela de 7 dias.
- Retenção de 30 dias — o humano fixou 7.
- Manter tudo exposto na API aberta — contraria a minimização agora que há uma finalidade com chave.

## Consequências
- Spec 000 deixa de ter "banco permanente" como fora de escopo para os agregados do bot (com teto de 7 dias).
- Página de privacidade e texto jurídico dependem do humano (P5, P6).
