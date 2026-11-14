- store: no desligamento, o ingest termina o lote em curso (commit + ack ou rollback + nak) e grava os pendentes
  antes de os SQLite fecharem; `Run` espera ingest, retenção e tempo real por até 8 s (task 206).
