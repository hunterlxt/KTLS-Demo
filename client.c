#include "config.h"

int main(int argc, char *argv[]) {
    init_openssl();
    // init arguments
    if (argc != 3) {
        printf("usage: ./client [IP] [Port]\n");
        exit(-1);
    }
    char *ip = argv[1];
    int port = atoi(argv[2]);

    int fd = create_client_socket(ip, port);

    SSL_CTX *ctx =
        init_ssl_ctx(TLS_client_method(), TLS1_2_VERSION, TLS1_2_VERSION);

    if (SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256") < 0) {
        printf("set cipher error");
        exit(-1);
    }

    ctx_config_key(ctx, (char *)"CA/cert.pem", (char *)"CA/key.pem");
    SSL *ssl = create_ssl(ctx, fd);
    if (SSL_connect(ssl) < 0) {
        printf("ssl connect error");
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    // receive data from server until read 0 bytes
    char buf[data_size];
    size_t buf_len = sizeof(buf);
    size_t count = 0;
    size_t sum_bytes = 0;
    int bytes = 0;
    do {
        bytes = SSL_read(ssl, buf, buf_len);
        if (bytes < 0) {
            printf("SSL Read error: %d\n", bytes);
            ERR_print_errors_fp(stderr);
            exit(-1);
        }
        sum_bytes += bytes;
        count++;
    } while (bytes > 0);
    printf("Round counts: %ld\nMsg recv: %ld KB\n", count - 1, sum_bytes/1024);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return 0;
}