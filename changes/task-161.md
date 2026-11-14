- capture: o filtro BPF de exclusão aceita frames curtos demais para ler as portas (cabeçalho IP incompleto, IHL
  inválido, extensão IPv6 além do fim, L4 cortado) em vez de descartá-los no kernel; o fuzz exige "sem porta
  excluída ⇒ aceito" (task 161).
