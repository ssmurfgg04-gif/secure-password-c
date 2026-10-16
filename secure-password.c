/* secure-password.c - backend-br "Senha segura" challenge in pure C.
 *
 * POST /validate-password {"password": "..."}
 *   204 quando a senha atende a todos os criterios
 *   400 com JSON listando os criterios nao atendidos
 *
 * build: cc -O2 -o secure-password secure-password.c
 * run:   ./secure-password 8080
 * deps:  apenas libc (POSIX sockets), sem bibliotecas externas
 */
#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int has_upper, has_lower, has_digit, has_special;

static void scan_password(const char *pw, size_t n)
{
    has_upper = has_lower = has_digit = has_special = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)pw[i];
        if (isupper(c)) has_upper = 1;
        else if (islower(c)) has_lower = 1;
        else if (isdigit(c)) has_digit = 1;
        else if (c > ' ' && c < 127) has_special = 1;  /* fora de letras/digitos/espaco */
    }
}

/* extrai o valor do campo "password" de um corpo JSON simples */
static int extract_password(const char *body, char *out, size_t outsz)
{
    const char *p = strstr(body, "\"password\"");
    if (!p) return -1;
    p = strchr(p + 10, '"');
    if (!p) return -1;
    p++;
    size_t n = 0;
    while (*p && *p != '"' && n + 1 < outsz) {
        if (*p == '\\' && p[1]) p++;  /* trata \" \\ etc. de forma simples */
        out[n++] = *p++;
    }
    out[n] = 0;
    return (int)n;
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 8080;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 1; }
    if (listen(fd, 16) < 0) { perror("listen"); return 1; }
    fprintf(stderr, "ouvindo na porta %d\n", port);

    for (;;) {
        int c = accept(fd, 0, 0);
        if (c < 0) continue;
        char buf[4096] = {0};
        ssize_t r = read(c, buf, sizeof buf - 1);
        if (r <= 0) { close(c); continue; }

        if (strncmp(buf, "POST", 4) == 0 && strstr(buf, "/validate-password")) {
            char pw[1024];
            int n = extract_password(buf, pw, sizeof pw);
            if (n < 0) {
                dprintf(c, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
                           "Content-Length: 43\r\n\r\n"
                           "{\"errors\":[\"corpo da requisicao invalido\"]}");
            } else {
                scan_password(pw, (size_t)n);
                if (n >= 8 && has_upper && has_lower && has_digit && has_special) {
                    dprintf(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
                } else {
                    char errs[512] = {0};
                    size_t off = 0;
#define ADD(cnd, msg) if (!(cnd)) off += (size_t)snprintf(errs + off, sizeof errs - off, "%s\"%s\"", off ? "," : "", msg)
                    ADD(n >= 8,      "a senha deve possuir pelo menos 08 caracteres");
                    ADD(has_upper,   "a senha deve conter pelo menos uma letra maiuscula");
                    ADD(has_lower,   "a senha deve conter pelo menos uma letra minuscula");
                    ADD(has_digit,   "a senha deve conter pelo menos um digito numerico");
                    ADD(has_special, "a senha deve conter pelo menos um caractere especial");
                    char body[600];
                    int bl = snprintf(body, sizeof body, "{\"errors\":[%s]}", errs);
                    dprintf(c, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
                               "Content-Length: %d\r\n\r\n%s", bl, body);
                }
            }
        } else {
            dprintf(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        }
        close(c);
    }
}
