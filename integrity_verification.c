#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HMAC_LENGTH SHA256_DIGEST_LENGTH
#define KEY_LENGTH 32        // Longueur de la clé pour AES-256
#define BUFFER_SIZE 1024     // Taille du tampon pour lire le fichier

// Fonction pour convertir une chaîne hexadécimale en tableau d'octets
void hex_to_bytes(const char *hex, unsigned char *bytes) {
    for (size_t i = 0; i < strlen(hex) / 2; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

// Fonction pour calculer l'HMAC
void compute_hmac(const unsigned char *data, size_t data_len, unsigned char *key, unsigned char *hmac) {
    HMAC(EVP_sha256(), key, KEY_LENGTH, data, data_len, hmac, NULL);
}

// Fonction pour vérifier l'HMAC
int verify_hmac(const unsigned char *data, size_t data_len, unsigned char *key, unsigned char *expected_hmac) {
    unsigned char computed_hmac[HMAC_LENGTH];
    compute_hmac(data, data_len, key, computed_hmac);
    return (memcmp(computed_hmac, expected_hmac, HMAC_LENGTH) == 0);
}

// Fonction principale pour tester la vérification d'intégrité
int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Utilisation : %s <fichier> <clé_hex> <hmac_hex>\n", argv[0]);
        return 1;
    }

    // Lire le fichier à vérifier
    const char *input_file = argv[1];
    unsigned char key[KEY_LENGTH];
    unsigned char expected_hmac[HMAC_LENGTH];

    // Convertir la clé et l'HMAC de hexadécimal à octets
    hex_to_bytes(argv[2], key);
    hex_to_bytes(argv[3], expected_hmac);

    FILE *in = fopen(input_file, "rb");
    if (!in) {
        perror("Échec d'ouverture du fichier");
        return 1;
    }

    // Lire le contenu du fichier
    unsigned char *data = malloc(BUFFER_SIZE);
    size_t total_bytes_read = fread(data, 1, BUFFER_SIZE, in);
    fclose(in);

    // Vérifier l'HMAC
    if (verify_hmac(data, total_bytes_read, key, expected_hmac)) {
        printf("L'intégrité du fichier est vérifiée avec succès.\n");
    } else {
        printf("Vérification de l'intégrité échouée : le fichier a été altéré.\n");
    }

    free(data);
    return 0;
}