- pkg: `readInt` do HPACK passivo limita a continuação como o x/net (deslocamento abaixo de 63); inteiros com
  continuação longa viram `ErrHPACKInteger` em vez de campos que o servidor recusou (task 169).
