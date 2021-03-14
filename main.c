
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

#define HOME "/etc/symbion/"
#define CERTF HOME "cert.pem"
#define KEYF HOME "key.pem"

#define CHK_NULL(x) if((x) == NULL) exit(1);
#define CHK_ERR(err, s) if((err) == -1) { perror(s); exit(1); }
#define CHK_SSL(err) if((err) == -1) { ERR_print_errors_fp(stderr); exit(2); }

char *server_addr = "192.168.4.48"; //"0.0.0.0";
int server_port = 12443;
//char *client_addr = "192.168.1.180"; //localhost";
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

int main(int argc, char **argv) {
    int pid;

logfile=fopen("log.bin","w");
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
    //fcntl(server_socket, F_SETFL, O_NONBLOCK);
    // return server_socket;


    //server_ssl_init();






    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();




    while (1) {



        char buffer[8192];


        Sctx = SSL_CTX_new(TLSv1_2_server_method());




        if (!Sctx) {
            ERR_print_errors_fp(stderr);
            exit(2);
        }

        if (SSL_CTX_use_certificate_file(Sctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(3);
        }

        if (SSL_CTX_use_PrivateKey_file(Sctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(4);
        }

        if (!SSL_CTX_check_private_key(Sctx)) {
            fprintf(stderr, "Private key does not match the certificate public keyn");
            exit(5);
        }

        int client = accept(server_socket, (struct sockaddr*) &server_sa, &server_sa_len);

        pid = fork();

        if (pid != 0) {
            signal(SIGCHLD, SIG_IGN);
            close(client);

        } else {

            if (client > 0) {
                //close(server_socket);

                printf("################################## Client Started #################################\n\n");

                setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof tv);
                setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char*) &tv, sizeof tv);

                Sssl = SSL_new(Sctx);

                SSL_set_fd(Sssl, client);



                //SSL_CTX_set_verify(Sctx, SSL_VERIFY_PEER, NULL);


                if (SSL_accept(Sssl) > 0) {

                    printf("%s\n\n", "SSL Handshake Complete.........................................................\n\n");

                    //   char buffer[MAXBYTE * sizeof (char)];//(char*) malloc(MAXBYTE * sizeof (char));

                    memset(buffer, '\0', sizeof (buffer));


                    /*     char *c = (char*) calloc(1, sizeof (char));
            do {
                           bytes = SSL_read(Sssl, c, 1);
                           if (bytes <= 0) break;
                           if (c == '\n') {
                               if (line_length == 0) {
                                   i++;
                                   break;
                               } else line_length = 0;
                           } else if (c != '\r') line_length++;

                           buffer[i++] = *c;
                           received += bytes;
                       } while (1);
                       free(c);
                     */

                    int bytes = 0;
                    int line_length = 0;
                    int i = 0;
                    int contlen = -1;
                    int bodylen = 0;

                    bytes = SSL_read(Sssl, buffer, sizeof (buffer) - 1);
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


                        char *saveptr;
                        char tmp_buf[sizeof (buffer) * sizeof (char)]; //(char*) malloc(MAXBYTE * sizeof (char));
                        char *tmppoint;
                        bzero(tmp_buf, sizeof (buffer));


                        memcpy(tmp_buf, buffer, sizeof (buffer) * sizeof (char));

                        strtok_r(tmp_buf, "\r\n", &saveptr);
                        char *line;
                        while ((line = strtok_r(saveptr, "\r\n", &saveptr))) {
                            if (strstr(line, "Host:")) {

                                strtok_r(line, " ", &line);

                                break;
                            }
                            tmppoint = saveptr;
                        }


                        printf("Host Name :  %s\n\n", line);



                        struct hostent* host = gethostbyname(line);


                        if (host != NULL) {
                            printf("%s\n\n", "DNS Success .........................................................\n\n");

                            int clientsock;

                            struct sockaddr_in Caddr;
                            clientsock = socket(AF_INET, SOCK_STREAM, 0);
                            memset(&Caddr, 0x00, sizeof (Caddr));
                            Caddr.sin_family = AF_INET;
                            Caddr.sin_port = htons(client_port);
                            Caddr.sin_addr.s_addr = *(long*) (host ->h_addr);

                            if (connect(clientsock, (struct sockaddr*) &Caddr, sizeof (Caddr)) == -1) {
                                printf("Cannot connect to Server");
                            }

                            // = CreateCsocket(host);

                            if (clientsock) {




                                Cctx = SSL_CTX_new(TLSv1_2_client_method());


                                Cssl = SSL_new(Cctx);

                                SSL_set_fd(Cssl, clientsock);


                                if (SSL_connect(Cssl) > 0) {


                                    int len;

                                    len = strlen(buffer);

                                    setsockopt(clientsock, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv, sizeof tv);
                                    setsockopt(clientsock, SOL_SOCKET, SO_SNDTIMEO, (const char*) &tv, sizeof tv);
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


                                SSL_shutdown(Cssl);

                                close(clientsock);
                                SSL_free(Cssl);
                                SSL_CTX_free(Cctx);


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
                // 
                perror("Unable to accept Client");
            }
            exit (0);
        }
         
    }

    close(server_socket);




}

