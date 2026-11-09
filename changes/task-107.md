- infra: o banco-modelo do verify-quick (`scripts/testdb`) nasce com as pragmas de criação do store
  (`auto_vacuum=INCREMENTAL` antes das migrations), que entram no hash e refazem o modelo uma vez; o teste de
  vacuum do store volta a usar o modelo (task 107).
