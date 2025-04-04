#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SALT_LENGTH 16
#define KEY_LENGTH 32 // Longueur de la clé dérivée (256 bits)
#define ITERATIONS 10000
#define PASSWORD_MAX_LENGTH 128

// Fonction pour générer un sel aléatoire
void generate_salt(unsigned char *salt) {
    if (!RAND_bytes(salt, SALT_LENGTH)) {
        fprintf(stderr, "Erreur lors de la génération du sel.\n");
        exit(EXIT_FAILURE);
    }
}

// Fonction pour dériver une clé à partir d'un mot de passe
void derive_key(const char *password, unsigned char *salt, unsigned char *key) {
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LENGTH, ITERATIONS, EVP_sha256(), KEY_LENGTH, key)) {
        fprintf(stderr, "Erreur lors de la dérivation de la clé.\n");
        exit(EXIT_FAILURE);
    }
}

// Fonction pour stocker la clé dans un fichier
void store_key(const char *filename, unsigned char *salt, unsigned char *key) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Échec d'ouverture du fichier pour écrire la clé");
        exit(EXIT_FAILURE);
    }
    fwrite(salt, 1, SALT_LENGTH, file); // Écrire le sel
    fwrite(key, 1, KEY_LENGTH, file);    // Écrire la clé
    fclose(file);
}