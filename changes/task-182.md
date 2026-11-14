- store: lote FSPB com `Fs-Format`/`Fs-Schema-Version` diferentes de `fspb1`/`1`, ou truncado, é descartado inteiro
  antes de aplicar registros; `Fs-Count` divergente avisa em `fs_store_batch_count_mismatch_total`; helper
  `event.CheckPacketHeaders` (task 182).
