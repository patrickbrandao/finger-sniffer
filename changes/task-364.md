- fix(bot): o casamento traefix ↔ store sem o início da conexão (forwardAuth antes do registro de conexão do
  traefix) não aceita mais a entrada `closed` da mesma origem e porta; a espera segue até o `opened` da conexão nova
  e o veredito deixa de levar o TCP e o `conn_id` da anterior (task 364).
