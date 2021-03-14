#include "opts.h"
#include "attrib.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <stdarg.h>
#include <netdb.h>

#include <signal.h>

#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include <memory.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdarg.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <malloc.h>
#include <bits/string3.h>

FILE *logfile;
#define serverQlen 15
#define MAXBYTE 12000

#define HOME "/home/lasitha/"
#define CERTF HOME  "cert.pem"
#define KEYF HOME  "key.pem"

#define CHK_NULL(x) if((x) == NULL) exit(1);
#define CHK_ERR(err, s) if((err) == -1) { perror(s); exit(1); }
#define CHK_SSL(err) if((err) == -1) { ERR_print_errors_fp(stderr); exit(2); }

char *server_addr = "192.168.2.20"; //"0.0.0.0";
int server_port = 12443;

int client_port = 443;

int server_socket;

struct sockaddr_in server_sa;
unsigned int server_sa_len;

int getHeaderValue(char *header, char *buf, char *value) {

    char *tmp = (char*) calloc(strlen(buf), sizeof (char));
    bcopy(buf, tmp, strlen(buf));

    char* line;

    while ((line = strtok_r(tmp, "\r\n", &tmp))) {
        if (strstr(line, header)) {
            strtok_r(NULL, " ", &line);
            strcpy(value, line);
            return 1;

        }

    }
    return 0;
}

int server_init(char *addr, int port, int maxconn) {
    struct sockaddr_in server;
    long ipaddr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("socket()");
        exit(1);
    }
    server.sin_family = AF_INET;
    inet_pton(AF_INET, addr, &ipaddr);
    server.sin_addr.s_addr = ipaddr;
    //    server.sin_addr.s_addr=htons(INADDR_ANY);
    server.sin_port = htons(port);
    if (bind(server_socket, (struct sockaddr *) &server, sizeof (server)) < 0) {
        perror("bind()");
        exit(1);
    }
    listen(server_socket, maxconn);
    //fcntl(server_socket, F_SETFL, O_NONBLOCK);
    return server_socket;
}

int CreateCsocket(struct hostent *host) {
    int sd;
    struct sockaddr_in Caddr;
    sd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&Caddr, 0, sizeof (Caddr));
    Caddr.sin_family = AF_INET;
    Caddr.sin_port = htons(client_port);
    Caddr.sin_addr.s_addr = *(long*) (host ->h_addr);

    if (connect(sd, (struct sockaddr*) &Caddr, sizeof (Caddr)) == -1) {
        printf("Cannot connect to Server");
    }
    return sd;
}

typedef struct pxy_conn_ctx {
    unsigned int clienthello_search : 1; /* 1 if waiting for hello */
    unsigned int clienthello_found : 1; /* 1 if conn upgrade to SSL */

    /* server name indicated by client in SNI TLS extension */
    char *sni;



    /* original certificate */

    X509 *origcrt;


    opts_t *opts;
} pxy_conn_ctx_t;

static void pxy_sslctx_setoptions(SSL_CTX *sslctx, pxy_conn_ctx_t *ctx) {
    SSL_CTX_set_options(sslctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
    SSL_CTX_set_options(sslctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /* SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    SSL_CTX_set_options(sslctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /* SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(sslctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /* SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
    SSL_CTX_set_options(sslctx, SSL_OP_NO_TICKET);
#endif /* SSL_OP_NO_TICKET */

    SSL_CTX_set_cipher_list(sslctx, ctx->opts->ciphers);
}

static SSL_CTX *
pxy_srcsslctx_create(pxy_conn_ctx_t *ctx, X509 *crt, STACK_OF(X509) * chain,
        EVP_PKEY *key) {
    SSL_CTX *sslctx = SSL_CTX_new(ctx->opts->sslmethod);
    if (!sslctx)
        return NULL;

    pxy_sslctx_setoptions(sslctx, ctx);


    SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_SERVER |
            SSL_SESS_CACHE_NO_INTERNAL);
#ifdef USE_SSL_SESSION_ID_CONTEXT
    SSL_CTX_set_session_id_context(sslctx, (void *) (&ssl_session_context),
            sizeof (ssl_session_context));
#endif /* USE_SSL_SESSION_ID_CONTEXT */

#ifndef OPENSSL_NO_DH
    if (ctx->opts->dh) {
        SSL_CTX_set_tmp_dh(sslctx, ctx->opts->dh);
    } else {
        SSL_CTX_set_tmp_dh_callback(sslctx, ssl_tmp_dh_callback);
    }
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
    if (ctx->opts->ecdhcurve) {
        EC_KEY *ecdh = ssl_ec_by_name(ctx->opts->ecdhcurve);
        SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
        EC_KEY_free(ecdh);
    } else {
        EC_KEY *ecdh = ssl_ec_by_name(NULL);
        SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
        EC_KEY_free(ecdh);
    }
#endif /* !OPENSSL_NO_ECDH */
    SSL_CTX_use_certificate(sslctx, crt);
    SSL_CTX_use_PrivateKey(sslctx, key);
    for (int i = 0; i < sk_X509_num(chain); i++) {
        X509 *c = sk_X509_value(chain, i);
        //ssl_x509_refcount_inc(c); /* next call consumes a reference */
        SSL_CTX_add_extra_chain_cert(sslctx, c);
    }

    return sslctx;
}

static cert_t *
pxy_srccert_create(pxy_conn_ctx_t *ctx) {
    cert_t *cert = NULL;




    cert = cert_new();

    cert->crt = ssl_x509_forge(ctx->opts->cacrt, ctx->opts->cakey, ctx->origcrt, ctx->opts->key, NULL, ctx->opts->crlurl);


    cert_set_key(cert, ctx->opts->key);
    cert_set_chain(cert, ctx->opts->chain);



    return cert;
}

static SSL *pxy_srcssl_create(pxy_conn_ctx_t *ctx, SSL *origssl) {
    cert_t *cert;


    ctx->origcrt = SSL_get_peer_certificate(origssl);



    cert = pxy_srccert_create(ctx);
    if (!cert)
        return NULL;

    SSL_CTX *sslctx = pxy_srcsslctx_create(ctx, cert->crt, cert->chain,
            cert->key);
    cert_free(cert);

    SSL *ssl = SSL_new(sslctx);
    SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
    if (!ssl) {

        return NULL;
    }
#ifdef SSL_MODE_RELEASE_BUFFERS
    /* lower memory footprint for idle connections */
    SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */
    return ssl;
}

static SSL *
pxy_dstssl_create(pxy_conn_ctx_t *ctx) {
    SSL_CTX *sslctx;
    SSL *ssl;


    sslctx = SSL_CTX_new(SSLv23_client_method());

    if (!sslctx) {

        return NULL;
    }




    SSL_CTX_set_verify(sslctx, SSL_VERIFY_NONE, NULL);


    ssl = SSL_new(sslctx);
    SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
    if (!ssl) {

        return NULL;
    }
#ifndef OPENSSL_NO_TLSEXT
    if (ctx->sni) {
        SSL_set_tlsext_host_name(ssl, ctx->sni);
    }
#endif /* !OPENSSL_NO_TLSEXT */

#ifdef SSL_MODE_RELEASE_BUFFERS
    /* lower memory footprint for idle connections */
    SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */



    return ssl;
}

int main(int argc, char **argv) {
    int pid;

    opts_t *opts;
    opts = opts_new();


    EVP_PKEY_free(opts->cakey);
    opts->cakey = ssl_key_load(KEYF);

    opts->cacrt = ssl_x509_load(CERTF);
    //ssl_x509_refcount_inc(opts->cacrt);
    sk_X509_insert(opts->chain, opts->cacrt, 0);

    if (opts->cakey && opts->cacrt &&
            (X509_check_private_key(opts->cacrt, opts->cakey) != 1)) {
        printf("CA cert does not match key.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    opts->ciphers = strdup(DFLT_CIPHERS);

    opts->key = ssl_key_genrsa(1024);
    opts->sslmethod = SSLv23_server_method();


    pxy_conn_ctx_t *ctx = malloc(sizeof (pxy_conn_ctx_t));
    memset(ctx, 0, sizeof (pxy_conn_ctx_t));
    ctx->opts = opts;







    logfile = fopen("log.bin", "w");
    SSL_CTX *Cctx;
    SSL *Cssl;

    SSL_CTX *Sctx;
    SSL *Sssl;


    signal(SIGPIPE, SIG_IGN);
    struct timeval tv;
    tv.tv_sec = 2; // 2 seconds
    tv.tv_usec = 0;


    //server_init(server_addr, server_port, serverQlen);
    char *addr = server_addr;
    int port = server_port;
    int maxconn = serverQlen;
    struct sockaddr_in server;
    long ipaddr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("socket()");
        exit(1);
    }
    server.sin_family = AF_INET;
    inet_pton(AF_INET, addr, &ipaddr);
    server.sin_addr.s_addr = ipaddr;
    //    server.sin_addr.s_addr=htons(INADDR_ANY);
    server.sin_port = htons(port);
    if (bind(server_socket, (struct sockaddr *) &server, sizeof (server)) < 0) {
        perror("bind()");
        exit(1);
    }
    listen(server_socket, maxconn);

    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();




    while (1) {



        char buffer[8192];

        pxy_conn_ctx_t *Cctx = malloc(sizeof (pxy_conn_ctx_t));

        int client = accept(server_socket, (struct sockaddr*) &server_sa, &server_sa_len);


        unsigned char buf[1024];
        ssize_t n;
        const unsigned char *chello;
        int rv;

        n = recv(client, buf, sizeof (buf), MSG_PEEK); // Take hello massages containing data from client and store in buff.
        if (n == -1) {
            printf("Error peeking on fd, aborting "
                    "connection\n");
            //evutil_closesocket(fd);
            //pxy_conn_ctx_free(ctx, 1);
            return;
        }
        if (n == 0) {
            /* socket got closed while we were waiting */
            //evutil_closesocket(fd);
            //pxy_conn_ctx_free(ctx, 1);
            return;
        }

        rv = ssl_tls_clienthello_parse(buf, n, 0, &chello, &Cctx->sni); // Identify hello massage and append to chello field.   
        if ((rv == 1) && !chello) {
            printf("Peeking did not yield a (truncated) "
                    "ClientHello message, "
                    "aborting connection\n");
            //evutil_closesocket(fd);
            //pxy_conn_ctx_free(ctx, 1);
            return;
        }

        /*  pid = fork();

         if (pid != 0) {
              //wait(NULL);
              signal(SIGCHLD, SIG_IGN);
              close(client);

          } else { 
         */
        if (client > 0) {
            //close(server_socket);

            printf("################################## Client Started #################################\n\n");


            char clientip[20];
            struct sockaddr_in addr;
            bzero((char *) &addr, sizeof (addr));
            addr.sin_family = AF_INET;
            socklen_t addr_sr = sizeof (addr);
            getsockopt(client, SOL_IP, 80, &addr, &addr_sr);
            printf("Original Dest IP address is: %s\n", inet_ntoa(addr.sin_addr));


            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof tv);
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char*) &tv, sizeof tv);






            int clientsock;

            struct sockaddr_in Caddr;
            clientsock = socket(AF_INET, SOCK_STREAM, 0);
            memset(&Caddr, 0x00, sizeof (Caddr));
            Caddr.sin_family = AF_INET;
            Caddr.sin_port = htons(client_port);
            Caddr.sin_addr.s_addr = addr.sin_addr.s_addr; // *(long*) (inet_ntoa(addr.sin_addr));


            if (connect(clientsock, (struct sockaddr*) &Caddr, sizeof (Caddr)) == -1) {
                printf("Cannot connect to Server");
            }



            if (clientsock) {

                //SSL_CTX *Cctx;
                SSL *Cssl = pxy_dstssl_create(Cctx);
                // Cctx = SSL_CTX_new(SSLv23_client_method());


                //Cssl = SSL_new(Cctx);






                SSL_set_fd(Cssl, clientsock);

                if (SSL_connect(Cssl) > 0) {


                    Sssl = malloc(sizeof (SSL));

                    Sssl = pxy_srcssl_create(ctx, Cssl);


                    SSL_set_fd(Sssl, client);

                    SSL_shutdown(Cssl);

                    close(clientsock);
                    SSL_free(Cssl);
                    ///  SSL_CTX_free(Cctx);

                    if (SSL_accept(Sssl) > 0) {

                        printf("%s\n\n", "SSL Handshake Complete.........................................................\n\n");

                        //   char buffer[MAXBYTE * sizeof (char)];//(char*) malloc(MAXBYTE * sizeof (char));

                        memset(buffer, '\0', sizeof (buffer));



                        int bytes = 0;
                        int line_length = 0;
                        int i = 0;
                        int contlen = -1;
                        int bodylen = 0;

                        bytes = SSL_read(Sssl, buffer, 1);
                        bytes += SSL_read(Sssl, buffer + 1, sizeof (buffer) - 1);

                        buffer[bytes] = 0x00;

                        if (bytes > 0 || SSL_pending(Sssl) > 0) {
                            while (i <= bytes) {

                                if (buffer[i] == '\n') {
                                    if (line_length == 0) {
                                        i++;
                                        break;
                                    } else line_length = 0;
                                } else if (buffer[i] != '\r') line_length++;
                                i++;
                            }

                            bodylen = -i;
                            bodylen += bytes;


                            //  printf("%s\n\n", "Client Request.........................................................\n\n");






                            //  struct hostent* host = gethostbyname(line);


                            if (addr.sin_addr.s_addr != NULL) {
                                printf("%s\n\n", "DNS Success .........................................................\n\n");

                                int clientsock1;

                                struct sockaddr_in Caddr;
                                clientsock1 = socket(AF_INET, SOCK_STREAM, 0);
                                memset(&Caddr, 0x00, sizeof (Caddr));
                                Caddr.sin_family = AF_INET;
                                Caddr.sin_port = htons(client_port);
                                Caddr.sin_addr.s_addr = addr.sin_addr.s_addr; // *(long*) (inet_ntoa(addr.sin_addr));

                                if (connect(clientsock1, (struct sockaddr*) &Caddr, sizeof (Caddr)) == -1) {
                                    printf("Cannot connect to Server");
                                }

                                // = CreateCsocket(host);

                                if (clientsock1) {




                                    Cctx = SSL_CTX_new(SSLv23_client_method());


                                    Cssl = SSL_new(Cctx);

                                    SSL_set_fd(Cssl, clientsock1);

                                    if (SSL_connect(Cssl) > 0) {










                                        int len;

                                        len = strlen(buffer);

                                        setsockopt(clientsock1, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof tv);
                                        setsockopt(clientsock1, SOL_SOCKET, SO_SNDTIMEO, (const char*) &tv, sizeof tv);
                                        char value[15];
                                        memset(value, '\0', sizeof (value));



                                        SSL_write(Cssl, buffer, bytes);

                                        if (getHeaderValue("Content-Length:", buffer, &value)) {


                                            int contlen = atoi(value);

                                            while (contlen > bodylen) {
                                                memset(buffer, '\0', sizeof (buffer));
                                                bytes = SSL_read(Sssl, buffer, sizeof (buffer) - 1);

                                                if (bytes <= 0) break;
                                                bodylen += bytes;
                                                SSL_write(Cssl, buffer, bytes);
                                                bytes = 0;

                                            }

                                        }
                                        if (len) {
                                            memset(buffer, '\0', sizeof (buffer));

                                            contlen = -1;
                                            bodylen = 0;
                                            bytes = 0;
                                            bytes = SSL_read(Cssl, buffer, sizeof (buffer) - 1);

                                            printf("Server Responded ..................%d......................\n\n", bytes);

                                            if (bytes > 0) {
                                                //fprintf(logfile , "Server Response : \n\n");
                                                //fwrite("Server Response : \n\n",strlen("Server Response : \n\n"),10,logfile);
                                                memset(value, '\0', sizeof (value));

                                                if (getHeaderValue("Content-Length:", buffer, value)) {
                                                    contlen = atoi(value);

                                                    i = 0;
                                                    line_length = 0;

                                                    while (i <= bytes) {

                                                        if (buffer[i] == '\n') {
                                                            if (line_length == 0) {
                                                                i++;
                                                                break;
                                                            } else line_length = 0;
                                                        } else if (buffer[i] != '\r') line_length++;
                                                        i++;
                                                    }

                                                    bodylen = -i;

                                                    printf("\n$$$$$$$$$$$$$ header length : %d $$$$$$$$$$$$$\n\n", i);
                                                    printf("$$$$$$$$$$$$$ ContLen %d $$$$$$$$$$$$$\n\n", contlen);

                                                }

                                                char trnsfcoding[10];
                                                memset(trnsfcoding, '\0', sizeof (trnsfcoding));

                                                getHeaderValue("Tranfer-Coding", buffer, &trnsfcoding);

                                                while (bytes > 0) {

                                                    bodylen += bytes;
                                                    //


                                                    //fwrite(buffer,bytes,10,logfile);
                                                    //fprintf(logfile , "%s",buffer);


                                                    //
                                                    int iswrite = SSL_write(Sssl, buffer, bytes);

                                                    //printf("content : %s\n\n", buffer);

                                                    if (iswrite == -1) {
                                                        printf("write fail to client");
                                                        break;
                                                    }

                                                    if (contlen > -1) {

                                                        if (contlen <= bodylen) {
                                                            break;

                                                        }

                                                    } else if (trnsfcoding == NULL || trnsfcoding != "chunked") {

                                                        if (strstr(buffer, "0\r\n\r\n") != NULL) {
                                                            break;
                                                        }
                                                    }
                                                    memset(buffer, '\0', sizeof (buffer) * sizeof (char));
                                                    bytes = 0;
                                                    bytes = SSL_read(Cssl, buffer, sizeof (buffer) - 1);

                                                }


                                            }
                                            printf("Server Responded body  ..................%i......................\n\n", bodylen);


                                            printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ Request Complete @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\n");
                                            //fprintf(logfile , );
                                            //fwrite("End Server Response : \n\n\n\n\n",strlen("End Server Response : \n\n\n\n\n"),10,logfile);
                                        } else {
                                            printf("Failed to write to server.....");
                                        }
                                    } else {
                                        printf("connection fail to server");

                                    }





                                } else {
                                    printf("Create Server connection Failed.....");
                                }
                            } else {
                                printf("DNS Failed.....");
                            }

                        } else {
                            printf("Failed to read client Request.....");
                        }


                    } else {

                        printf("Error ssl handshake.\n");
                    }

                    printf("################################## Client Closed #################################\n\n");
                    close(client);
                    SSL_free(Sssl);
                    SSL_CTX_free(Sctx);





                } else {
                    SSL_shutdown(Cssl);

                    close(clientsock);
                    SSL_free(Cssl);
                    SSL_CTX_free(Cctx);

                }


            }








        } else {
            // 
            perror("Unable to accept Client");
        }
        // exit (0);
        //} 

    }

    close(server_socket);




}

