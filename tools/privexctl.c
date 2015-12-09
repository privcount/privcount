/**
 * privexctl is a tool for dumping privex stats from Tor and loading into the privex DC from file later
 *
 * to build: "cmake . && make"
 *
 * this can also be run inside of shadow as a plugin by using something like
 *   <plugin id="privexctl" path="path/to/privexctl" />
 * in the shadow.config.xml file as usual
 */

//#define _GNU_SOURCE
#include "stdio.h"
#include "stdlib.h"
#include "sys/socket.h"
#include "sys/types.h"
#include "netinet/in.h"
#include "netdb.h"
#include "string.h"
#include "unistd.h"
#include "errno.h"
#include "arpa/inet.h"
#include <sys/epoll.h>

static int privex_sockfd = -1;
static int privex_port = -1;
static int privex_epollfd = -1;

static int setup_privex_client() {

    struct sockaddr_in serv_addr;

    if ((privex_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Privex Error : Could not create socket!\n");
        return EXIT_FAILURE;
    }

    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons((uint16_t) privex_port);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Privex Error : inet_pton error occured!\n");
        close(privex_sockfd);
        privex_sockfd = -1;
        return EXIT_FAILURE;
    }

    if (connect(privex_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Privex Error : Connect failed!\n");
        close(privex_sockfd);
        privex_sockfd = -1;
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Privex Connection : Success!\n");

    /* start watching the socket */
    privex_epollfd = epoll_create(1);
    if (privex_epollfd < 0) {
        fprintf(stderr, "Privex Error : unable to start client: error in epoll_create: %s\n", strerror(errno));
        close(privex_sockfd);
        privex_sockfd = -1;
        return EXIT_FAILURE;
    }

    /* specify the events to watch for on this socket.
     * the client wants to know when it can write to the server */
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.fd = privex_sockfd;

    if(epoll_ctl(privex_epollfd, EPOLL_CTL_ADD, privex_sockfd, &ev) < 0) {
        fprintf(stderr, "Privex Error : unable to start client: error in epoll_ctl: %s\n", strerror(errno));
        close(privex_sockfd);
        privex_sockfd = -1;
        close(privex_epollfd);
        privex_epollfd = -1;
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Privex Epoll : Success!\n");

    return EXIT_SUCCESS;
}

static int tell_privex(char* sendBuff, size_t sendBuffLen) {
    // If the privex socket is not yet set up or was broken for some reason try to
    // connect to it again
    if (privex_sockfd < 0 || privex_epollfd < 0) {
        if(setup_privex_client() != EXIT_SUCCESS) {
            fprintf(stderr, "Privex Error : Server not running or not on port expected!\n");
            return EXIT_FAILURE;
        }
    }

    size_t remaining = sendBuffLen;
    struct epoll_event ev;

    while(remaining > 0) {
        /* clear the event space */
        memset(&ev, 0, sizeof(struct epoll_event));

        /* wait for an event on the privex descriptor */
        int nReadyFDs = epoll_wait(privex_epollfd, &ev, 1, -1);
        if(nReadyFDs == -1) {
            fprintf(stderr, "Privex Error : error in client epoll_wait: %s\n", strerror(errno));
            close(privex_sockfd);
            privex_sockfd = -1;
            close(privex_epollfd);
            privex_epollfd = -1;
            return EXIT_FAILURE;
        }

        /* activate if something is ready */
        if(nReadyFDs > 0) {
            ssize_t written = write(privex_sockfd, &sendBuff[sendBuffLen-remaining], remaining);
            if (written < 0) {
                fprintf(stderr, "Privex Error : Could not write to the socket: %s\n", strerror(errno));
                close(privex_sockfd);
                privex_sockfd = -1;
                close(privex_epollfd);
                privex_epollfd = -1;
                return EXIT_FAILURE;
            }

            remaining -= (size_t)written;
        }
    }

    return EXIT_SUCCESS;
}

static int load(int port) {
    privex_port = port;

    char * line = NULL;
    size_t len = 0;
    ssize_t readlen;
    int result = EXIT_SUCCESS;

    while (result == EXIT_SUCCESS && (readlen = getline(&line, &len, stdin)) != -1) {
       //fprintf(stdout, "%s", line);
       result = tell_privex(line, readlen);
    }

    if(line) {
        free(line);
    }

    return result;
}

static int setup_privex_server() {
    /* create the socket and get a socket descriptor */
    privex_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (privex_sockfd < 0) {
        fprintf(stderr, "Privex Error : unable to start server: error in socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /* setup the socket address info, client has outgoing connection to server */
    struct sockaddr_in bindAddress;
    memset(&bindAddress, 0, sizeof(bindAddress));
    bindAddress.sin_family = AF_INET;
    bindAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bindAddress.sin_port = htons((uint16_t)privex_port);

    /* bind the socket to the server port */
    int res = bind(privex_sockfd, (struct sockaddr *) &bindAddress, sizeof(bindAddress));
    if (res == -1) {
        fprintf(stderr, "Privex Error : unable to start server: error in bind: %s\n", strerror(errno));
        close(privex_sockfd);
        privex_sockfd = -1;
        return EXIT_FAILURE;
    }

    /* set as server socket that will listen for clients */
    res = listen(privex_sockfd, 100);
    if (res == -1) {
        fprintf(stderr, "Privex Error : unable to start server: error in listen: %s\n", strerror(errno));
        close(privex_sockfd);
        privex_sockfd = -1;
        return EXIT_FAILURE;
    }

    /* start watching the socket */
    privex_epollfd = epoll_create(1);
    if (privex_epollfd < 0) {
        fprintf(stderr, "Privex Error : unable to start server: error in epoll_create: %s\n", strerror(errno));
        close(privex_sockfd);
        privex_sockfd = -1;
        return EXIT_FAILURE;
    }

    /* specify the events to watch for on this socket.
     * the server wants to know when a client is connecting. */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = privex_sockfd;

    res = epoll_ctl(privex_epollfd, EPOLL_CTL_ADD, privex_sockfd, &ev);
    if(res == -1) {
        fprintf(stderr, "Privex Error : unable to start server: error in epoll_ctl: %s\n", strerror(errno));
        close(privex_sockfd);
        privex_sockfd = -1;
        close(privex_epollfd);
        privex_epollfd = -1;
        return EXIT_FAILURE;
    }

    /* success! */
    return EXIT_SUCCESS;
}

static int echo_data() {
    if (privex_sockfd < 0 || privex_epollfd < 0) {
        if(setup_privex_server() != EXIT_SUCCESS) {
            fprintf(stderr, "Privex Error : problem running or not on port expected!\n");
            return EXIT_FAILURE;
        }
    }

    size_t buffLen = 8192;
    char readBuff[buffLen];

    ssize_t numRead = read(privex_sockfd, readBuff, buffLen);
    if(numRead < 0) {
        fprintf(stderr, "Privex Error : Could not read from the socket: %s\n", strerror(errno));
        close(privex_sockfd);
        privex_sockfd = -1;
        close(privex_epollfd);
        privex_epollfd = -1;
        return EXIT_FAILURE;
    }

    if(numRead > 0) {
        size_t numWritten = fwrite(readBuff, numRead, (size_t)1, stdout);
        if(numRead != numWritten) {
            fprintf(stderr, "Privex Error : Could not write to stdout: %s\n", strerror(errno));
            close(privex_sockfd);
            privex_sockfd = -1;
            close(privex_epollfd);
            privex_epollfd = -1;
            return EXIT_FAILURE;
        }
    }
}

static int dump(int port) {
    privex_port = port;

    size_t buffLen = 8192;
    char readBuff[buffLen];
    struct epoll_event ev;

    while(1) {
        /* clear the event space */
        memset(&ev, 0, sizeof(struct epoll_event));

        /* wait for an event on the privex descriptor */
        int nReadyFDs = epoll_wait(privex_epollfd, &ev, 1, -1);

        if(nReadyFDs == -1) {
            fprintf(stderr, "Privex Error : error in client epoll_wait: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        /* activate if something is ready */
        if(nReadyFDs > 0) {
            if(echo_data() != EXIT_SUCCESS) {
                return EXIT_FAILURE;
            }
        }
    }

    // never reached
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    if(argc == 3 && strncasecmp(argv[1], "dump", 4) == 0) {
        return dump(atoi(argv[2]));
    } else if(argc == 3 && strncasecmp(argv[1], "load", 4) == 0) {
        return load(atoi(argv[2]));
    } else {
        fprintf(stderr, "Privex Error : argv format error, expected: %s <'dump'|'load'> <privex_port>\n", argv[0]);
        return EXIT_FAILURE;
    }
}
