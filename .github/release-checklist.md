# Checklist de release

Quem conduz: architect (task 072 para a `v0.1.0`). Infra mantém o processo (task 070).
`make release` não cria tag nem publica nada; a tag é o último passo antes do deploy.

## Antes
- [ ] Tarefas da fase concluídas e mergeadas; `./tasks/` sem nada `em-andamento` para esta versão.
- [ ] `main` local atualizada (`git checkout main && git pull`), árvore limpa.
- [ ] `make verify-full ARGS="--e2e"` verde (inclui `linux_priv` na vps602 e a matriz da spec 017).
- [ ] CI verde na `main` (jobs `verify-full` e `release-build`).
- [ ] Teste de carga de 10 min (spec 017, ADR 0022) com as metas de RNF da spec 000 atingidas; relatório em `test/load/RESULTS.md`.
- [ ] Conferência FoxIO `ja4`/`tshark` (JA3, JA4, JA4T, Akamai) de curl, Go, Chrome e Firefox registrada.
- [ ] Auditoria spec × implementação do reviewer sem pendência bloqueante.
- [ ] Fragmentos `changes/task-*.md` juntados no `CHANGELOG.md` na seção `[X.Y.Z] - AAAA-MM-DD` e apagados.
- [ ] PR de release com os três itens de sucesso da spec 000 ("Objetivos e medida de sucesso") e as evidências.

## Pacote
- [ ] Depois do merge do PR de release, na `main` atualizada: `make release VERSION=vX.Y.Z`
      (confere árvore limpa e `origin/main`, roda `verify-full`, compila e gera em `dist/`):
      - `finger-sniffer-vX.Y.Z-linux-amd64.tar.gz` (5 binários, units, sysctl, journald, rede, nats.conf, htdocs,
        `SHA256SUMS`);
      - `finger-sniffer-vX.Y.Z-linux-amd64.SHA256SUMS` e `.tar.gz.sha256`.
- [ ] `make repro-check` verde (dois builds seguidos e um em outro diretório com o mesmo SHA-256).

## Tag
- [ ] Tag **anotada** no commit do pacote, com as linhas `bin/` do `SHA256SUMS` na mensagem
      (o workflow `release` confere o rebuild do CI contra elas):
      ```
      { echo "finger-sniffer vX.Y.Z"; echo; grep ' bin/' dist/finger-sniffer-vX.Y.Z-linux-amd64.SHA256SUMS; } >tmp/tag-msg
      git tag -a vX.Y.Z -F tmp/tag-msg
      git push origin vX.Y.Z
      ```
- [ ] Workflow `release` da tag verde: rebuild no Linux igual ao `SHA256SUMS` do tar e da anotação, `-version` dos
      5 binários mostra `vX.Y.Z`.

## Deploy e smoke
- [ ] `git checkout --detach vX.Y.Z && make deploy` (o `git describe` dá `vX.Y.Z`, sem `-dirty`).
- [ ] `ssh -p 48022 root@vps602.tmsoft.com.br /finger-sniffer/bin/finger-sniffer-web -version` mostra `vX.Y.Z`
      (idem para os outros 4).
- [ ] Smoke do deploy ok e `GET http://vps602.tmsoft.com.br:9001/api/v1/health` com os 5 serviços `ok`.
- [ ] Voltar à `main` (`git checkout main`).
