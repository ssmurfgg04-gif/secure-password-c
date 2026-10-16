# Senha Segura em C

Solução do desafio [Senha segura](https://github.com/backend-br/desafios/blob/master/secure-password/PROBLEM.md)
do backend-br, em C puro: um servidor HTTP minimalista com apenas sockets POSIX,
sem nenhuma biblioteca externa (sem framework, sem JSON lib, sem dependências).

## Requisitos atendidos

- [x] `POST /validate-password` recebe `{"password": "..."}`
- [x] `204 No Content` quando a senha atende a todos os critérios
- [x] `400 Bad Request` com `{"errors":[...]}` listando exatamente os critérios
      não atendidos (tamanho mínimo 08, maiúscula, minúscula, dígito, especial)
- [x] um único arquivo, ~110 linhas, build com um comando

## Como rodar

```bash
cc -O2 -o secure-password secure-password.c
./secure-password 8080
```

## Testando

```bash
curl -i -X POST localhost:8080/validate-password \
  -d '{"password":"vYQIYxO&p$7fI^r"}'
# HTTP/1.1 204 No Content

curl -i -X POST localhost:8080/validate-password -d '{"password":"abc"}'
# HTTP/1.1 400 + {"errors":["a senha deve possuir pelo menos 08 caracteres",
#  "a senha deve conter pelo menos uma letra maiuscula", ...]}
```

Observação: o exemplo do enunciado (`vYQIYxO&p$yfI^r`) não contém dígito
numérico, então falha no critério de dígito — a implementação segue os
requisitos formais da seção "Requisitos", que pedem o dígito.

## Decisões

- **C sem dependências**: o ponto do desafio é o serviço, então o servidor
  HTTP (parse de request line + extração do campo `password`) fica em ~40
  linhas; a validação em si é uma passada única pela string.
- **Erros precisos**: em vez de um booleano genérico, a resposta 400 lista
  todos os critérios que falharam, como o enunciado sugere.
- **`c > ' '` para caracteres especiais**: espaço não conta como especial;
  qualquer byte imprimível fora de letras e dígitos conta.
