#include "config.h"

int main(int argc, char *argv[]) {
    init_openssl();
    // init arguments
    if (argc != 3) {
        printf("usage: ./server [Port] [File]\n");
        exit(-1);
    }
    int port = atoi(argv[1]);
    char *file_name = argv[2];
    int filefd = open(file_name, O_RDONLY);
    if (filefd < 0) {
        printf("open file failed\n");
        exit(-1);
    }

    int listenfd = create_listen_socket(port);

    int fd = create_server_socket(listenfd);

    SSL_CTX *ctx =
        init_ssl_ctx(TLS_server_method(), TLS1_2_VERSION, TLS1_2_VERSION);

    ctx_config_key(ctx, (char *)"CA/cert.pem", (char *)"CA/key.pem");

    SSL *ssl = create_ssl(ctx, fd);
    if (SSL_accept(ssl) <= 0) {
        printf("SSL fail to accecpt\n");
    } else {
        int bytes = 0;
        // write test
        const char reply[] = "This is SSL server";
        bytes = SSL_write(ssl, reply, strlen(reply));
        printf("Bytes send(%d)\n", bytes);
        // sendfile test
        if (!SSL_enable_ktls(ssl, fd, TX_MODE)) {
            exit(-1);
        }
        bytes = SSL_sendfile(ssl, filefd, 0, 100);
        printf("Bytes send(%d)\n", bytes);
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    close(listenfd);
    close(filefd);
}