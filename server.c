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
        // BIO *bio = SSL_get_wbio(ssl);
        // if (bio == NULL)
        //     printf("bio is null\n");
        // auto ret = BIO_ctrl(bio, BIO_CTRL_GET_KTLS_SEND, 0, NULL);
        // printf("ret: %d\n", ret);
        // if (BIO_get_ktls_send(bio))
        //     printf("Using KTLS...\n");
        // else
        //     printf("Not using KTLS...\n");
        int bytes = 0;
        const char reply[] = "This is SSL server";
        bytes = SSL_write(ssl, reply, strlen(reply));
        printf("Bytes send(%d)\n", bytes);

        if (!ktls_enable(ssl, fd)) {
            printf("KTLS enable failed\n");
            exit(-1);
        }
        bytes = sendfile(fd, filefd, 0, 100);
        printf("Bytes send(%d)\n", bytes);
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    close(listenfd);
    close(filefd);
}