- fix(store): respostas JSON da API com prazo de escrita de 60 s (`writeJSON`/`writeProbe`): cliente que pede e
  não lê não prende mais o handler e a resposta na memória (task 319, item 1).
