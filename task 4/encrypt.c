#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ITERATIONS 10000
#define KEY_LENGTH 32
#define SALT_LENGTH 16
#define BUFFER_SIZE 4096

void derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LENGTH, ITERATIONS, EVP_sha256(), KEY_LENGTH, key);
}

void encrypt_file(const char *input_path, const char *output_path, const char *password) {
    // Génération du sel
    unsigned char salt[SALT_LENGTH];
    if (!RAND_bytes(salt, SALT_LENGTH)) {
        fprintf(stderr, "Erreur de génération du sel\n");
        exit(EXIT_FAILURE);
    }

    // Dérivation de la clé
    unsigned char key[KEY_LENGTH];
    derive_key(password, salt, key);

    // Initialisation du chiffrement
    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (!RAND_bytes(iv, EVP_MAX_IV_LENGTH)) {
        fprintf(stderr, "Erreur de génération de l'IV\n");
        exit(EXIT_FAILURE);
    }

    FILE *in = fopen(input_path, "rb");
    FILE *out = fopen(output_path, "wb");
    if (!in || !out) {
        perror("Erreur d'ouverture de fichier");
        exit(EXIT_FAILURE);
    }

    // Écriture de l'IV
    fwrite(iv, 1, EVP_MAX_IV_LENGTH, out);

    // Configuration du chiffrement
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    // Configuration du HMAC (version moderne OpenSSL 3.0+)
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *hmac_ctx = EVP_MAC_CTX_new(hmac);
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC_init(hmac_ctx, key, KEY_LENGTH, params);

    // Mise à jour du HMAC avec l'IV
    EVP_MAC_update(hmac_ctx, iv, EVP_MAX_IV_LENGTH);

    // Chiffrement et calcul du HMAC
    unsigned char in_buf[BUFFER_SIZE], out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int len, out_len;

    while ((len = fread(in_buf, 1, BUFFER_SIZE, in)) > 0) {
        EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, len);
        fwrite(out_buf, 1, out_len, out);
        EVP_MAC_update(hmac_ctx, out_buf, out_len);
    }

    EVP_EncryptFinal_ex(ctx, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, out);
    EVP_MAC_update(hmac_ctx, out_buf, out_len);

    // Finalisation du HMAC
    size_t hmac_len;
    unsigned char hmac_value[EVP_MAX_MD_SIZE];
    EVP_MAC_final(hmac_ctx, hmac_value, &hmac_len, sizeof(hmac_value));

    // Stockage du keystore
    FILE *keystore = fopen("keystore.bin", "wb");
    fwrite(salt, 1, SALT_LENGTH, keystore);
    fwrite(hmac_value, 1, hmac_len, keystore);
    fclose(keystore);

    // Nettoyage
    EVP_CIPHER_CTX_free(ctx);
    EVP_MAC_CTX_free(hmac_ctx);
    EVP_MAC_free(hmac);
    fclose(in);
    fclose(out);
    memset(key, 0, KEY_LENGTH);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input> <output> <password>\n", argv[0]);
        return EXIT_FAILURE;
    }
    encrypt_file(argv[1], argv[2], argv[3]);
    printf("Fichier chiffré avec succès.\n");
    return EXIT_SUCCESS;
}