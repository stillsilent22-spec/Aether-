/*
 * aether_system_service.c
 *
 * Native Aether local service for Windows/Linux.
 * Provides a simple TCP JSON API for invariant observation and analysis.
 * Gossip and DHT are handled by the overlay manager service.
 *
 * Build:
 *   Linux: gcc -std=c89 -Wall -O2 -o aether_system_service aether_system_service.c
 *   Windows: gcc -std=c89 -Wall -O2 -o aether_system_service.exe aether_system_service.c -lws2_32
 *
 * Usage:
 *   aether_system_service --port 40011
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")
#define CLOSE_SOCKET closesocket
#define SOCKET_ERRNO WSAGetLastError()
#define socklen_t int
#else
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#define CLOSE_SOCKET close
#define SOCKET_ERRNO errno
#endif

#define DEFAULT_TCP_PORT 40011
#define MAX_LINE 1024
#define MAX_INVARIANT_TEXT 128
#define SAMPLE_BYTES 4096
#define DATA_SAMPLE_PATH "data/vault/aether_seed_v1.bin"

static volatile int keep_running = 1;

static void handle_shutdown(int signum) {
    (void)signum;
    keep_running = 0;
}

static double clamp01(double value) {
    if (value < 0.0) return 0.0;
    if (value > 1.0) return 1.0;
    return value;
}

static double compute_entropy(const unsigned char *data, size_t len) {
    if (!data || len == 0) return 0.0;
    unsigned int counts[256] = {0};
    size_t i;
    for (i = 0; i < len; i++) {
        counts[data[i]]++;
    }
    double entropy = 0.0;
    for (i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / (double)len;
        entropy -= p * log(p) / log(2.0);
    }
    return entropy;
}

static double compute_periodicity(const unsigned char *data, size_t len) {
    if (!data || len < 4) return 0.0;
    size_t max_lag = len < 64 ? len : 64;
    double best = 0.0;
    size_t lag;
    for (lag = 1; lag < max_lag; lag++) {
        size_t matches = 0;
        size_t compared = 0;
        size_t i;
        for (i = 0; i + lag < len; i++) {
            compared++;
            if (data[i] == data[i + lag]) matches++;
        }
        if (compared == 0) continue;
        double score = (double)matches / (double)compared;
        if (score > best) best = score;
    }
    return clamp01(best);
}

static size_t read_sample_data(unsigned char *buffer, size_t max_len) {
    FILE *f = fopen(DATA_SAMPLE_PATH, "rb");
    if (!f) {
        return 0;
    }
    size_t got = fread(buffer, 1, max_len, f);
    fclose(f);
    return got;
}

static int has_substring(const char *text, const char *needle) {
    if (!text || !needle) return 0;
    return strstr(text, needle) != NULL;
}

static void build_response(char *out, size_t out_len, const char *status, const char *body) {
    snprintf(out, out_len, "{\"status\":\"%s\",\"body\":%s}\n", status, body ? body : "{}");
}

static int create_tcp_socket(int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        CLOSE_SOCKET(sock);
        return INVALID_SOCKET;
    }
    if (listen(sock, 8) == SOCKET_ERROR) {
        CLOSE_SOCKET(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

static void handle_tcp_client(SOCKET client, int port) {
    char buffer[MAX_LINE];
    int received = recv(client, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        CLOSE_SOCKET(client);
        return;
    }
    buffer[received] = '\0';
    unsigned char sample[SAMPLE_BYTES];
    size_t sample_len = read_sample_data(sample, sizeof(sample));
    double entropy = compute_entropy(sample, sample_len);
    double periodicity = compute_periodicity(sample, sample_len);
    char status_text[128];
    char body[256];
    if (has_substring(buffer, "status")) {
        snprintf(body, sizeof(body), "{\"version\":\"0.1\",\"port\":%d,\"uptime\":%ld}", port, (long)time(NULL));
        build_response(status_text, sizeof(status_text), "ok", body);
        send(client, status_text, (int)strlen(status_text), 0);
    } else if (has_substring(buffer, "invariants")) {
        snprintf(body, sizeof(body), "{\"entropy\":%.4f,\"periodicity\":%.4f}", entropy, periodicity);
        build_response(status_text, sizeof(status_text), "ok", body);
        send(client, status_text, (int)strlen(status_text), 0);
    } else {
        build_response(status_text, sizeof(status_text), "error", "{\"message\":\"unknown command\"}");
        send(client, status_text, (int)strlen(status_text), 0);
    }
    CLOSE_SOCKET(client);
}

int main(int argc, char **argv) {
    int tcp_port = DEFAULT_TCP_PORT;
    int arg;
    for (arg = 1; arg < argc; arg++) {
        if (strcmp(argv[arg], "--port") == 0 && arg + 1 < argc) {
            tcp_port = atoi(argv[++arg]);
        }
    }

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

#ifndef _WIN32
    signal(SIGINT, handle_shutdown);
    signal(SIGTERM, handle_shutdown);
#endif

    printf("[SERVICE] Starting Aether System Service on port %d\n", tcp_port);
    SOCKET tcp_sock = create_tcp_socket(tcp_port);
    if (tcp_sock == INVALID_SOCKET) {
        fprintf(stderr, "[SERVICE] TCP socket failed\n");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    fd_set read_fds;
    while (keep_running) {
        FD_ZERO(&read_fds);
        FD_SET(tcp_sock, &read_fds);
        int ready = select((int)tcp_sock + 1, &read_fds, NULL, NULL, NULL);
        if (ready < 0) {
            int err = SOCKET_ERRNO;
#ifdef _WIN32
            if (err == WSAEINTR) continue;
#else
            if (err == EINTR) continue;
#endif
            fprintf(stderr, "[SERVICE] select failed %d\n", err);
            break;
        }
        if (FD_ISSET(tcp_sock, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addrlen = sizeof(client_addr);
            SOCKET client = accept(tcp_sock, (struct sockaddr*)&client_addr, &addrlen);
            if (client != INVALID_SOCKET) {
                handle_tcp_client(client, tcp_port);
            }
        }
    }

    printf("[SERVICE] Shutting down\n");
    CLOSE_SOCKET(tcp_sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
