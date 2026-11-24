- fix(infra): units com caminhos por serviço (ADR 0075 item 2): `ReadWritePaths` só com o que cada unit grava e
  `InaccessiblePaths` no resto de `var/` (capture e dns sem `var/`, só o bot alcança `var/bot`), mais `ProtectClock`,
  `ProtectKernelLogs`, `ProtectHostname`, `UMask=0077` e `ProtectProc=invisible` no NATS e nos 6 serviços (task 355).
