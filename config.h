#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/ssl.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* NOTE: data_size <= size of your test file */
size_t data_size = 16384;
size_t round_count = 1024 * 512;

int create_listen_socket(int port) {
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    int addr_len = sizeof(addr);
    if (sockfd < 0) {
        printf("Fail to create socket");
        exit(-1);
    }
    if (bind(sockfd, (struct sockaddr *)&addr, addr_len) < 0) {
        printf("Fail to bind");
        exit(-1);
    }
    if (getsockname(sockfd, (struct sockaddr *)&addr, (socklen_t *)&addr_len) <
        0) {
        printf("Fail to getsockname");
        exit(-1);
    }
    if (listen(sockfd, 1) < 0) {
        printf("Unable to listen");
        exit(-1);
    }
    printf("Serving port %d...\n", port);
    return sockfd;
}

int create_server_socket(int listenfd) {
    int serverfd = accept(listenfd, NULL, 0);
    return serverfd;
}

int create_client_socket(char *ip, int port) {
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int clientfd = socket(AF_INET, SOCK_STREAM, 0);
    if (clientfd < 0) {
        printf("Fail to create socket");
        exit(-1);
    }
    if (connect(clientfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("Fail to connect server");
        exit(-1);
    }
    return clientfd;
}

SSL_CTX *init_ssl_ctx(const SSL_METHOD *method, int min_proto_version,
                      int max_proto_version) {
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("Fail to create SSL context");
        exit(-1);
    }
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION)) {
        printf("set proto version error");
        exit(-1);
    }
    return ctx;
}

void ctx_config_key(SSL_CTX *ctx, char *certfile, char *privkeyfile) {
    if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, privkeyfile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
}

SSL *create_ssl(SSL_CTX *ctx, int fd) {
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("create ssl error");
        exit(-1);
    }
    SSL_set_fd(ssl, fd);
    return ssl;
}

void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}
