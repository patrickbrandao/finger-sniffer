- store: TCP estabelecido fica na tabela por `max(FS_IDLE_DEFAULT, FS_IDLE_MAX)` + 30 s (630 s com os padrões), sem
  fechar antes do web uma conexão com `idle=`; QUIC sem close continua em `FS_IDLE_DEFAULT` + 30 s (task 151).
