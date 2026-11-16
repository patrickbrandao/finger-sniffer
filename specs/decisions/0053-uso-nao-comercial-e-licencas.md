# 0053 — Uso não comercial e licenças (JA4+, ja4db, traefik)

Status: aceita (item 4, licença do fork: com o projeto traefix, ver 0054)
Data: 2026-11-16

## Contexto
Decisão do humano (entrevista, seção 3): o serviço é **não comercial**; seguimos com JA4+ (FoxIO License 1.1) e a
ja4db, registrando a condição numa ADR. O espelho já calcula JA4, JA4_r, JA4_o, JA4H e JA4T (specs 008–013). O fork
do traefik herda a licença MIT do upstream (ADR 0048).

## Decisão
1. **Condição de uso**: o espelho e a API de vereditos são oferecidos sem cobrança e para uso não comercial. As
   chaves de API (ADR 0051) só são emitidas para uso não comercial; a página do espelho, o `docs/` e a resposta do
   `GET /bot/v1/openapi.yaml` (campo `info.x-terms`) dizem isso. Nenhum recurso pago, plano ou cobrança entra sem
   ADR nova e decisão do humano.
2. **JA4+**: o JA4 (TLS do cliente) é BSD-3-Clause; as demais da família usadas aqui (JA4H, JA4T) seguem a FoxIO
   License 1.1, que permite o uso não comercial. O `NOTICE` do repositório cita a FoxIO e as duas licenças; uso
   comercial por terceiros exige licença da FoxIO e é responsabilidade deles (os termos da API dizem isso).
3. **ja4db**: usada como fonte de sinal nos termos que a FoxIO publicar; o NOTICE a cita; a redistribuição da base
   depende da licença (pendência P4 da spec 018; até lá, não é versionada nem redistribuída, ADR 0050 item 2).
4. **Traefik**: o fork mantém `LICENSE.md` (MIT) e o aviso de copyright do upstream; o nosso `NOTICE` do fork lista
   as mudanças; a imagem leva `org.opencontainers.image.licenses=MIT` e a origem.
5. **Listas de IP**: publicadas para uso público pelos donos (buscadores, nuvens); o bot só as consulta e não as
   redistribui pela API (devolve só se um IP está nelas).

## Alternativas consideradas
- Trocar JA4H/JA4T por fingerprints sem licença restritiva — perde comparabilidade com a FoxIO, pedida pela spec 000.
- Cobrar pelas chaves — o humano decidiu não comercial.

## Consequências
- Qualquer uso comercial futuro reabre esta ADR e as licenças da FoxIO.
