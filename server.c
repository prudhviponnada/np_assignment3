/*
 * server.c
 * Simple TCP chat server implementing a tiny line-based protocol used for
 * teaching/assignment purposes. Clients must:
 *  - connect, receive the server greeting: "Hello 1\n"
 *  - send "NICK <nickname>\n" to authenticate (nickname validation enforced)
 *  - after authentication, send "MSG <text>\n" to broadcast messages
 *
 * The server keeps a small fixed-size client table and uses select() to
 * multiplex listening and client sockets in a single-threaded loop.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <regex.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>

#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024
#define MAX_NICK_LEN 12
#define MAX_MSG_LEN 255

/* Per-client state held in an array */
typedef struct {
    int fd;                             /* connected socket for the client */
    char nick[MAX_NICK_LEN + 1];        /* authenticated nickname (zero-terminated) */
    int authenticated;                  /* boolean: has client sent valid NICK? */
} client_t;

/* Global server state */
static client_t clients[MAX_CLIENTS];
static int client_count = 0;
static regex_t nick_regex;              /* compiled regex to validate nicknames */
static int server_fd = -1;              /* listening socket fd */

/*
 * rstrip_crlf
 * Remove trailing CR/LF characters from a string in-place. Useful for
 * sanitizing network-delivered nicknames or lines which may contain \r or \n.
 */
static void rstrip_crlf(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\r' || s[len - 1] == '\n')) {
        s[len - 1] = '\0';
        len--;
    }
}

/*
 * cleanup
 * Close all client sockets, the listening socket, free regex resources and
 * exit. Registered as a signal handler for SIGINT to ensure tidy shutdown.
 */
void cleanup(int sig) {
    (void)sig;
    for (int i = 0; i < client_count; i++) {
        close(clients[i].fd);
    }
    if (server_fd != -1) close(server_fd);
    regfree(&nick_regex);
    exit(0);
}

/*
 * validate_nickname
 * Ensure the provided nickname meets length constraints and matches the
 * allowed character set via a compiled regular expression. The function is
 * defensive: it copies the input into a local buffer and strips CR/LF.
 * Returns 1 when nickname is valid, 0 otherwise.
 */
int validate_nickname(const char *nick_in) {
    if (!nick_in) return 0;

    /* Copy into local buffer for safe processing */
    char temp[BUFFER_SIZE];
    strncpy(temp, nick_in, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    rstrip_crlf(temp);

    size_t ln = strlen(temp);
    if (ln == 0 || ln > MAX_NICK_LEN)
        return 0;

    /* Use regex to allow A-Z a-z 0-9 and underscore, 1..12 chars */
    return regexec(&nick_regex, temp, 0, NULL, 0) == 0;
}

/*
 * broadcast_message
 * Send `msg` to all authenticated clients except the sender (by index).
 * Returns the number of clients successfully written to.
 */
int broadcast_message(const char *msg, int sender_index) {
    int sent = 0;
    for (int i = 0; i < client_count; i++) {
        if (i != sender_index && clients[i].authenticated) {
            ssize_t n = write(clients[i].fd, msg, strlen(msg));
            if (n > 0) sent++;
        }
    }
    return sent;
}

/*
 * add_client
 * Add a newly accepted client socket to the in-memory client array. If the
 * server is already at capacity the socket is closed and -1 returned.
 */
int add_client(int fd) {
    if (client_count >= MAX_CLIENTS) {
        close(fd);
        return -1;
    }
    clients[client_count].fd = fd;
    clients[client_count].authenticated = 0;
    clients[client_count].nick[0] = '\0';
    client_count++;
    return 0;
}

/*
 * remove_client
 * Remove a client by array index: close its socket and compact the array.
 */
void remove_client(int index) {
    close(clients[index].fd);
    for (int i = index; i < client_count - 1; i++) {
        clients[i] = clients[i + 1];
    }
    client_count--;
}

/*
 * main
 * - parse bind address (HOST:PORT)
 * - compile nickname validation regex
 * - bind and listen on a TCP socket
 * - single-threaded select()-based loop handles accept + client I/O
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s HOST:PORT\nExample: %s 0.0.0.0:5010\n", argv[0], argv[0]);
        fflush(stderr);
        return 1;
    }

    /* Split host:port */
    char *colon = strchr(argv[1], ':');
    if (!colon) {
        fprintf(stderr, "Invalid address (expect host:port): %s\n", argv[1]);
        fflush(stderr);
        return 1;
    }
    size_t host_len = colon - argv[1];
    if (host_len == 0 || host_len >= NI_MAXHOST) {
        fprintf(stderr, "Invalid host in %s\n", argv[1]);
        fflush(stderr);
        return 1;
    }
    char bind_host[NI_MAXHOST];
    char bind_port[NI_MAXSERV];
    memcpy(bind_host, argv[1], host_len);
    bind_host[host_len] = '\0';
    strncpy(bind_port, colon + 1, sizeof(bind_port) - 1);
    bind_port[sizeof(bind_port) - 1] = '\0';

    /* Compile regex allowing letters, digits, and underscores, 1–12 chars */
    if (regcomp(&nick_regex, "^[A-Za-z0-9_]{1,12}$", REG_EXTENDED) != 0) {
        fprintf(stderr, "Regex compilation failed\n");
        fflush(stderr);
        return 1;
    }

    /* ensure cleanup on Ctrl-C */
    signal(SIGINT, cleanup);

    /* Resolve bind address and bind to the first successful addr */
    struct addrinfo hints, *res, *rp;
    int sfd = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      /* allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;      /* OK to bind wildcard if host is NULL; host provided here */

    int gai = getaddrinfo(bind_host, bind_port, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "getaddrinfo(%s,%s): %s\n", bind_host, bind_port, gai_strerror(gai));
        fflush(stderr);
        regfree(&nick_regex);
        return 1;
    }

    /* Try each resolved address until bind succeeds */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) continue;

        int opt = 1;
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            close(sfd);
            sfd = -1;
            continue;
        }

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            server_fd = sfd;
            break;
        }

        close(sfd);
        sfd = -1;
    }
    freeaddrinfo(res);

    if (server_fd == -1) {
        fprintf(stderr, "ERROR: failed to bind to %s:%s\n", bind_host, bind_port);
        fflush(stderr);
        regfree(&nick_regex);
        return 1;
    }

    if (listen(server_fd, SOMAXCONN) == -1) {
        perror("listen");
        fflush(stderr);
        cleanup(0);
        return 1;
    }

    printf("Server listening on %s:%s\n", bind_host, bind_port);
    fflush(stdout);

    const char *hello = "Hello 1\n";  /* exact greeting required by tests */

    /* Main loop: use select() to handle accept and client sockets */
    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        int maxfd = server_fd;

        /* Add current clients to fd set */
        for (int i = 0; i < client_count; ++i) {
            FD_SET(clients[i].fd, &readfds);
            if (clients[i].fd > maxfd) maxfd = clients[i].fd;
        }

        int sel = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (sel == -1) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        /* New connection ready to accept */
        if (FD_ISSET(server_fd, &readfds)) {
            struct sockaddr_storage cliaddr;
            socklen_t clilen = sizeof(cliaddr);
            int cfd = accept(server_fd, (struct sockaddr *)&cliaddr, &clilen);
            if (cfd != -1) {
                /* send greeting */
                send(cfd, hello, strlen(hello), 0);
                if (add_client(cfd) == 0) {
                    printf("New client connected (total: %d)\n", client_count);
                    fflush(stdout);
                } else {
                    close(cfd);
                }
            }
        }

        /* Handle readable clients. Iterate backwards so removing a client
         * doesn't affect yet-to-be-processed indices. */
        for (int i = client_count - 1; i >= 0; --i) {
            int cfd = clients[i].fd;
            if (!FD_ISSET(cfd, &readfds)) continue;

            char buf[BUFFER_SIZE];
            ssize_t n = read(cfd, buf, sizeof(buf) - 1);
            if (n <= 0) {
                /* Client disconnected or read error */
                printf("Client disconnected\n");
                fflush(stdout);
                remove_client(i);
                continue;
            }
            buf[n] = '\0';

            /* tokenize by CR/LF to handle multiple commands in one read */
            char *saveptr = NULL;
            char *cmd = strtok_r(buf, "\r\n", &saveptr);
            while (cmd) {
                /* NICK command: authenticate the client */
                if (strncmp(cmd, "NICK ", 5) == 0) {
                    char *nick = cmd + 5;
                    /* Trim leading spaces */
                    while (*nick == ' ') nick++;
                    if (validate_nickname(nick)) {
                        strncpy(clients[i].nick, nick, MAX_NICK_LEN);
                        clients[i].nick[MAX_NICK_LEN] = '\0';
                        clients[i].authenticated = 1;
                        send(cfd, "OK\n", 3, 0);
                        printf("Client %s authenticated\n", clients[i].nick);
                        fflush(stdout);
                    } else {
                        const char err[] = "ERR Invalid nickname\n";
                        send(cfd, err, strlen(err), 0);
                        fflush(stderr);
                    }

                /* MSG command: broadcast to other authenticated clients */
                } else if (strncmp(cmd, "MSG ", 4) == 0 && clients[i].authenticated) {
                    char *msg = cmd + 4;
                    size_t mlen = strlen(msg);
                    if (mlen <= MAX_MSG_LEN) {
                        char out[BUFFER_SIZE];
                        int outlen = snprintf(out, sizeof(out), "MSG %s %s\n", clients[i].nick, msg);
                        if (outlen > 0 && outlen < (int)sizeof(out)) {
                            broadcast_message(out, i);
                            printf("Broadcast from %s: %s\n", clients[i].nick, msg);
                            fflush(stdout);
                        }
                    } else {
                        const char err[] = "ERROR Message too long (max 255 chars)\n";
                        send(cfd, err, strlen(err), 0);
                        fflush(stderr);
                    }

                /* If the client hasn't authenticated yet, instruct them to send NICK */
                } else if (!clients[i].authenticated) {
                    const char err[] = "ERROR Authenticate with NICK first\n";
                    send(cfd, err, strlen(err), 0);
                    fflush(stderr);

                /* Unknown command (authenticated client) */
                } else {
                    const char err[] = "ERROR Unknown command\n";
                    send(cfd, err, strlen(err), 0);
                    fflush(stderr);
                }

                cmd = strtok_r(NULL, "\r\n", &saveptr);
            }
        }
    }

    cleanup(0);
    return 0;
}
