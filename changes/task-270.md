- Base própria de fingerprints (`internal/bot/lists/known_clients.json`, spec 018, ADR 0050): 15 medidas de curl
  (OpenSSL e LibreSSL), Go, Chrome, Firefox (h1/h2/h3), python-requests e Chrome headless, geradas por
  `TestF8KnownClients` com `FS_E2E_UPDATE=1`; formato e regra de regravação conferidos no verify-quick (task 270).
