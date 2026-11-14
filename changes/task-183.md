- infra: comentário do `nats.conf` descreve o stream `FS_EVENTS` pela lista explícita de subjects (ADR 0017) e
  `pkg/event/subjects.go` deixa de citar a versão antiga do asyncapi; teste em `deploy/` impede a volta de
  `fs.v1.>` (task 183).
