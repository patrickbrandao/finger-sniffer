- test: `TestH2RawFrames`, `TestH2ALPN` e `TestH2Instants` escolhem o evento `http2.stream` pelo `stream_id` em vez
  da posição; acabou o pânico intermitente no CI quando os streams chegam fora de ordem (task 202).
