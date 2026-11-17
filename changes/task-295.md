- bot: rules `v1.3` (ADR 0060) — `ja4h_library` compara também o `ja4h_ab` recalculado sem `Origin` e `Referer` pela
  ordem dos campos (`detail` com `(normalized)`); curl, Go e python-requests saem `bot` 70 e o Googlebot falso `bot` 80
  pelo probe. O e2e da F8 confere que o veredito do probe não chega ao feed.
