- store: o desligamento da API não falha mais com "context deadline exceeded" quando uma conexão aceita fica
  sem pedido (varredura de porta, outro processo na porta do teste): vencido o prazo gracioso, a API fecha o que
  resta e registra aviso; corrige o `TestStoreShutdownWaitsIngest` instável no CI (task 222).
