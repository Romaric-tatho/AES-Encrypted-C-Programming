// #include <openssl/evp.h>
#include <openssl/rand.h>
// #include <stdio.h>
#include <stdlib.h>
// #include <string.h>

#define KEY_LENGTH 32 // Longueur de la clé pour AES-256
#define IV_LENGTH 16  // Longueur du vecteur d'initialisation pour AES
#define BUFFER_SIZE 1024

// Fonction pour crypter le fichier
void encrypt_file(const char *input_file, const char *output_file, const unsigned char *key) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        perror("Échec d'ouverture du fichier");
        return;
    }

    // Générer un vecteur d'initialisation aléatoire
    unsigned char iv[IV_LENGTH];
    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Erreur lors de la génération du IV.\n");
        fclose(in);
        fclose(out);
        return;
    }

    // Écrire le IV dans le fichier de sortie
    fwrite(iv, sizeof(iv), 1, out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char ciphertext[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int len;

    while (1) {
        size_t read = fread(buffer, 1, sizeof(buffer), in);
        if (read <= 0) break;

        EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, read);
        fwrite(ciphertext, 1, len, out);
    }

    EVP_EncryptFinal_ex(ctx, ciphertext, &len);
    fwrite(ciphertext, 1, len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

// Fonction pour générer une clé aléatoire
void generate_key(unsigned char *key) {
    if (!RAND_bytes(key, KEY_LENGTH)) {
        fprintf(stderr, "Erreur lors de la génération de la clé.\n");
        exit(1);
    }
}