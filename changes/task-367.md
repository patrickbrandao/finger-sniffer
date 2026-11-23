- bot: no modo `block` o 403 do forwardAuth é mínimo — corpo `{"error":"forbidden"}`, sem `X-Traefix-Verdict`,
  `-Score`, `-Signals` nem os `X-Fs-*`, só `X-Traefix-Deny: 1`; o perfil do traefix passa a
  `denyRequiresResponseHeader: X-Traefix-Deny` (task 367, ADR 0074, openapi 0.7.0).
