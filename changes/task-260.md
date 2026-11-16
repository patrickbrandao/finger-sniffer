- test: `TestF5Fingerprints` liga a remontagem TCP fora de ordem do tshark/ja4; o ClientHello do Chrome cujo primeiro
  segmento se perde no caminho e é retransmitido deixava as ferramentas sem saída e virava divergência falsa;
  golden `f5-clienthello-retransmit.pcap` em `TestF5ToolsOutOfOrderClientHello` (task 260).
