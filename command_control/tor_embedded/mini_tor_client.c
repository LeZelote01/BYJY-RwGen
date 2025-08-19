#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <time.h>

#define TOR_PORT 9050
#define MAX_CIRCUITS 5
#define MAX_NODES 100
#define CELL_SIZE 512

typedef struct {
    char ip[16];
    unsigned short port;
    char fingerprint[41]; // 40 hex chars + null terminator
    char identity_key[256];
} TorNode;

typedef struct {
    int id;
    TorNode nodes[3]; // Entry, middle, exit
    SSL *ssl_connections[3];
    time_t created;
    time_t last_used;
} TorCircuit;

typedef struct {
    TorNode nodes[MAX_NODES];
    int node_count;
    TorCircuit circuits[MAX_CIRCUITS];
    int circuit_count;
} TorContext;

// Simulated Tor directory
TorNode directory[] = {
    {"185.220.103.7", 443, "BA44A889E64B93FAA2B114E02C2A279A8555C533", ""},
    {"199.249.230.142", 443, "D586D18309DED4CD6D57C18FDB97EFA96D330566", ""},
    {"193.11.114.43", 9001, "BD6A829255CB08E66FBE7D3748363586E46B3810", ""},
    // ... more nodes would be here
};

void initialize_ssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_ssl_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int connect_to_node(TorNode *node) {
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(node->port);
    inet_pton(AF_INET, node->ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        close(sock);
        return -1;
    }

    return sock;
}

SSL* establish_tls(int sock, const char *fingerprint) {
    SSL_CTX *ctx = create_ssl_context();
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    // Verify certificate fingerprint
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        fprintf(stderr, "No certificate presented\n");
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    X509_digest(cert, EVP_sha1(), digest, &digest_len);

    char hex_fingerprint[41];
    for (int i = 0; i < digest_len; i++) {
        sprintf(hex_fingerprint + (i*2), "%02X", digest[i]);
    }
    hex_fingerprint[40] = '\0';

    if (strcasecmp(hex_fingerprint, fingerprint) != 0) {
        fprintf(stderr, "Fingerprint mismatch: expected %s, got %s\n", 
                fingerprint, hex_fingerprint);
        X509_free(cert);
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    X509_free(cert);
    return ssl;
}

int create_circuit(TorContext *ctx) {
    if (ctx->circuit_count >= MAX_CIRCUITS) {
        return -1; // Max circuits reached
    }

    TorCircuit circuit;
    circuit.id = rand() % 0xFFFF;
    circuit.created = time(NULL);
    circuit.last_used = time(NULL);

    // Randomly select nodes
    for (int i = 0; i < 3; i++) {
        int node_idx = rand() % (sizeof(directory)/sizeof(TorNode));
        circuit.nodes[i] = directory[node_idx];
    }

    // Establish connections
    for (int i = 0; i < 3; i++) {
        int sock = connect_to_node(&circuit.nodes[i]);
        if (sock < 0) return -1;

        circuit.ssl_connections[i] = establish_tls(sock, circuit.nodes[i].fingerprint);
        if (!circuit.ssl_connections[i]) return -1;
    }

    // Perform Tor handshake and extend circuit
    // (Simplified - actual Tor uses complex crypto)
    char handshake[CELL_SIZE] = {0};
    snprintf(handshake, CELL_SIZE, "EXTEND %s:%d", 
             circuit.nodes[1].ip, circuit.nodes[1].port);
    SSL_write(circuit.ssl_connections[0], handshake, strlen(handshake));

    // Add to context
    ctx->circuits[ctx->circuit_count++] = circuit;
    return circuit.id;
}

int send_data(TorContext *ctx, int circuit_id, const char *data, size_t len) {
    for (int i = 0; i < ctx->circuit_count; i++) {
        if (ctx->circuits[i].id == circuit_id) {
            // Encrypt in layers (simplified)
            char encrypted[CELL_SIZE];
            snprintf(encrypted, CELL_SIZE, "RELAY %s", data);
            
            // Send through entry node
            SSL_write(ctx->circuits[i].ssl_connections[0], encrypted, strlen(encrypted));
            ctx->circuits[i].last_used = time(NULL);
            return 0;
        }
    }
    return -1;
}

int receive_data(TorContext *ctx, int circuit_id, char *buffer, size_t buf_size) {
    for (int i = 0; i < ctx->circuit_count; i++) {
        if (ctx->circuits[i].id == circuit_id) {
            // Receive from entry node
            int bytes = SSL_read(ctx->circuits[i].ssl_connections[0], buffer, buf_size - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                ctx->circuits[i].last_used = time(NULL);
                return bytes;
            }
            return -1;
        }
    }
    return -1;
}

void rotate_circuits(TorContext *ctx) {
    time_t now = time(NULL);
    for (int i = 0; i < ctx->circuit_count; i++) {
        // Rotate if circuit is older than 10 minutes or unused for 5
        if (now - ctx->circuits[i].created > 600 || 
            now - ctx->circuits[i].last_used > 300) {
            
            // Close connections
            for (int j = 0; j < 3; j++) {
                if (ctx->circuits[i].ssl_connections[j]) {
                    SSL_shutdown(ctx->circuits[i].ssl_connections[j]);
                    SSL_free(ctx->circuits[i].ssl_connections[j]);
                }
            }
            
            // Remove from list
            memmove(&ctx->circuits[i], &ctx->circuits[i+1], 
                   (ctx->circuit_count - i - 1) * sizeof(TorCircuit));
            ctx->circuit_count--;
            i--;
        }
    }
}

int main() {
    initialize_ssl();
    srand(time(NULL));
    
    TorContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    
    // Create initial circuit
    int circuit_id = create_circuit(&ctx);
    if (circuit_id < 0) {
        fprintf(stderr, "Failed to create circuit\n");
        return 1;
    }
    
    // Send sample request
    const char *request = "GET / HTTP/1.1\r\nHost: example.onion\r\n\r\n";
    send_data(&ctx, circuit_id, request, strlen(request));
    
    // Receive response
    char response[4096];
    int bytes = receive_data(&ctx, circuit_id, response, sizeof(response));
    if (bytes > 0) {
        printf("Received %d bytes:\n%.*s\n", bytes, bytes, response);
    }
    
    // Periodically rotate circuits
    while (1) {
        sleep(60);
        rotate_circuits(&ctx);
        if (ctx.circuit_count < 2) {
            create_circuit(&ctx);
        }
    }
    
    return 0;
}