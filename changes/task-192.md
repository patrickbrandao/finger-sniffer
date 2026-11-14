- dns: `optionTLVs` dimensiona o buffer pelo OPT recebido (`mdns.Len`) e sai cedo sem opções, em vez de alocar
  64 KiB por consulta com EDNS no laço do UDP; `BuildQuery` com EDNS cai de ~66 KiB para ~1 KiB por consulta, com
  o evento idêntico (task 192).
