- fix(store): `DELETE /api/v1/probes/{id}` confere pelo leitor se há o que apagar (probe inexistente não toca
  o escritor) e só um `DELETE` por vez disputa a conexão do escritor com o ingest (task 317).
