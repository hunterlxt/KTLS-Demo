#include "config.h"

int main(int argc, char *argv[]) {
    init_openssl();
    // init arguments
    if (argc != 4) {
        printf("usage: ./server [Mode] [File] "
               "[Port]\n\nMode:\n0-->SSL_sendfile\n1-->SSL_write");
        exit(-1);
    }
    int mode = atoi(argv[1]);
    int port = atoi(argv[3]);
    char *file_name = argv[2];

    // init and config SSL
    int listenfd = create_listen_socket(port);
    int fd = create_server_socket(listenfd);
    SSL_CTX *ctx =
        init_ssl_ctx(TLS_server_method(), TLS1_2_VERSION, TLS1_2_VERSION);
    ctx_config_key(ctx, (char *)"CA/cert.pem", (char *)"CA/key.pem");
    SSL *ssl = create_ssl(ctx, fd);

    // Send the file content over SSL in two ways.
    if (SSL_accept(ssl) <= 0) {
        printf("SSL fail to accecpt\n");
    } else {
        int bytes = 0;
        clock_t start, end;
        double cpu_time_used;
        size_t sum_bytes;

        if (mode == 0) {
            start = clock();
            sum_bytes = 0;
            if (!SSL_enable_ktls(ssl, fd, TX_MODE)) {
                exit(-1);
            }
            for (size_t i = 0; i < round_count; i++) {
                int filefd = open(file_name, O_RDONLY);
                bytes = SSL_sendfile(ssl, filefd, 0, data_size);
                sum_bytes += bytes;
                close(filefd);
            }
            printf("SSL_sendfile send %ld Bytes\n", sum_bytes);
            end = clock();
            cpu_time_used = (double)(end - start) / CLOCKS_PER_SEC;
            printf("SSL_sendfile cost time: %f\n", cpu_time_used);
        }
        if (mode == 1) {
            start = clock();
            sum_bytes = 0;
            for (size_t i = 0; i < round_count; i++) {
                int filefd = open(file_name, O_RDONLY);
                char send_buf[data_size];
                bytes = read(filefd, send_buf, data_size);
                bytes = SSL_write(ssl, send_buf, data_size);
                sum_bytes += bytes;
                close(filefd);
            }
            printf("SSL_write send %ld Bytes\n", sum_bytes);
            end = clock();
            cpu_time_used = (double)(end - start) / CLOCKS_PER_SEC;
            printf("SSL_write cost time: %f\n", cpu_time_used);
        }
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    close(listenfd);
}