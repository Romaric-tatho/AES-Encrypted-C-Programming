#include"../decrypt.h"
// #include <openssl/evp.h>
// #include <openssl/rand.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>

// #define KEY_LENGTH 32 // Longueur de la clé pour AES-256
// #define IV_LENGTH 16  // Longueur du vecteur d'initialisation pour AES
// #define BUFFER_SIZE 1024

// // Fonction pour convertir une chaîne hexadécimale en tableau d'octets
// void hex_to_bytes(const char *hex, unsigned char *bytes) {
//     for (size_t i = 0; i < strlen(hex) / 2; i++) {
//         sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
//     }
// }

// // Fonction pour déchiffrer le fichier
// int decrypt_file(const char *input_file, const char *output_file, const unsigned char *key) {
//     FILE *in = fopen(input_file, "rb");
//     FILE *out = fopen(output_file, "wb");
//     if (!in || !out) {
//         perror("Échec d'ouverture du fichier");
//         return 0;
//     }

//     // Lire l'IV depuis le début du fichier
//     unsigned char iv[IV_LENGTH];
//     fread(iv, sizeof(iv), 1, in);

//     EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
//     if (!ctx) {
//         fprintf(stderr, "Échec de la création du contexte.\n");
//         fclose(in);
//         fclose(out);
//         return 0;
//     }

//     // Initialiser le déchiffrement
//     if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
//         fprintf(stderr, "Échec de l'initialisation du déchiffrement.\n");
//         EVP_CIPHER_CTX_free(ctx);
//         fclose(in);
//         fclose(out);
//         return 0;
//     }

//     unsigned char buffer[BUFFER_SIZE];
//     unsigned char plaintext[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
//     int len;
//     int plaintext_len = 0;

//     // Déchiffrer le fichier d'entrée
//     while (1) {
//         size_t read = fread(buffer, 1, sizeof(buffer), in);
//         if (read <= 0) break;

//         if (EVP_DecryptUpdate(ctx, plaintext + plaintext_len, &len, buffer, read) != 1) {
//             fprintf(stderr, "Échec du déchiffrement.\n");
//             EVP_CIPHER_CTX_free(ctx);
//             fclose(in);
//             fclose(out);
//             return 0;
//         }
//         plaintext_len += len;
//     }

//     // Finaliser le déchiffrement
//     if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len) != 1) {
//         fprintf(stderr, "Échec du déchiffrement : remplissage invalide.\n");
//         EVP_CIPHER_CTX_free(ctx);
//         fclose(in);
//         fclose(out);
//         return 0;
//     }
//     plaintext_len += len;

//     // Écrire le contenu déchiffré dans le fichier de sortie
//     fwrite(plaintext, 1, plaintext_len, out);

//     EVP_CIPHER_CTX_free(ctx);
//     fclose(in);
//     fclose(out);
//     return 1; // Succès
// }

// Fonction principale
int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Utilisation : %s <fichier_a_dechiffrer> <fichier_sortie> <clé_hex>\n", argv[0]);
        return 1;
    }

    const char *input_file = argv[1];
    const char *output_file = argv[2];
    unsigned char key[KEY_LENGTH];

    // Convertir la clé de hexadécimal à octets
    hex_to_bytes(argv[3], key);

    if (decrypt_file(input_file, output_file, key)) {
        printf("Fichier déchiffré avec succès : %s\n", output_file);
    } else {
        printf("Échec du déchiffrement du fichier.\n");
    }

    return 0;
}