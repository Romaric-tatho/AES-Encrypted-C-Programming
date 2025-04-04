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

int verify_and_decrypt(const char *input_path, const char *output_path, const char *password) {
    // Lecture du keystore
    FILE *keystore = fopen("keystore.bin", "rb");
    if (!keystore) {
        perror("Keystore introuvable");
        return 0;
    }

    unsigned char salt[SALT_LENGTH], stored_hmac[EVP_MAX_MD_SIZE];
    fread(salt, 1, SALT_LENGTH, keystore);
    size_t hmac_len = fread(stored_hmac, 1, EVP_MAX_MD_SIZE, keystore);
    fclose(keystore);

    // Dérivation de la clé
    unsigned char key[KEY_LENGTH];
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LENGTH, ITERATIONS, EVP_sha256(), KEY_LENGTH, key);

    // Vérification du HMAC
    FILE *in = fopen(input_path, "rb");
    if (!in) {
        perror("Erreur d'ouverture du fichier chiffré");
        memset(key, 0, KEY_LENGTH);
        return 0;
    }

    unsigned char iv[EVP_MAX_IV_LENGTH];
    fread(iv, 1, EVP_MAX_IV_LENGTH, in);

    // HMAC moderne OpenSSL 3.0+
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *hmac_ctx = EVP_MAC_CTX_new(hmac);
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC_init(hmac_ctx, key, KEY_LENGTH, params);
    EVP_MAC_update(hmac_ctx, iv, EVP_MAX_IV_LENGTH);

    unsigned char in_buf[BUFFER_SIZE], computed_hmac[EVP_MAX_MD_SIZE];
    size_t len;

    while ((len = fread(in_buf, 1, BUFFER_SIZE, in)) > 0) {
        EVP_MAC_update(hmac_ctx, in_buf, len);
    }

    size_t computed_hmac_len;
    EVP_MAC_final(hmac_ctx, computed_hmac, &computed_hmac_len, sizeof(computed_hmac));
    EVP_MAC_CTX_free(hmac_ctx);
    EVP_MAC_free(hmac);

    if (hmac_len != computed_hmac_len || memcmp(stored_hmac, computed_hmac, hmac_len) != 0) {
        fprintf(stderr, "Erreur: Le fichier a été modifié!\n");
        fclose(in);
        memset(key, 0, KEY_LENGTH);
        return 0;
    }

    // Déchiffrement
    rewind(in);
    fread(iv, 1, EVP_MAX_IV_LENGTH, in);
    
    FILE *out = fopen(output_path, "wb");
    if (!out) {
        perror("Erreur de création du fichier de sortie");
        fclose(in);
        memset(key, 0, KEY_LENGTH);
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int out_len;

    while ((len = fread(in_buf, 1, BUFFER_SIZE, in)) > 0) {
        EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, len);
        fwrite(out_buf, 1, out_len, out);
    }

    EVP_DecryptFinal_ex(ctx, out_buf, &out_len);
    fwrite(out_buf, 1, out_len, out);

    // Nettoyage
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    memset(key, 0, KEY_LENGTH);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input> <output> <password>\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (verify_and_decrypt(argv[1], argv[2], argv[3])) {
        printf("Fichier déchiffré avec succès.\n");
        return EXIT_SUCCESS;
    } else {
        printf("Échec: Fichier corrompu ou mot de passe incorrect.\n");
        return EXIT_FAILURE;
    }
}