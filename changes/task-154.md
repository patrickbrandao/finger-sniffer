- store: o teto `FS_STORE_MAX_BYTES` apaga do mais antigo para o mais novo entre conexões encerradas, consultas DNS
  e pacotes avulsos; um banco dominado por DNS volta ao teto sem levar as conexões recentes, e o laço para quando
  só restam conexões abertas (task 154).
