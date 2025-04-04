#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>

#define ITERATIONS 100000
#define KEY_LENGTH 32
#define SALT_LENGTH 16
#define IV_LENGTH 16
#define BUFFER_SIZE 4096
#define HMAC_LENGTH 32

// Désactive l'affichage du mot de passe
void disable_echo() {
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

// Réactive l'affichage
void enable_echo() {
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

// Vérifie si un fichier existe
int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

// Dérive une clé à partir d'un mot de passe et d'un sel
void derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LENGTH,
                     ITERATIONS, EVP_sha256(), KEY_LENGTH, key);
}

// Fonction de chiffrement
int encrypt_file(const char *input_path, const char *output_path, const char *password) {
    // Vérifie que le fichier source existe
    if (!file_exists(input_path)) {
        fprintf(stderr, "Erreur: Fichier source introuvable\n");
        return 0;
    }

    // Génère un sel et un IV aléatoires
    unsigned char salt[SALT_LENGTH], iv[IV_LENGTH];
    if (!RAND_bytes(salt, SALT_LENGTH) || !RAND_bytes(iv, IV_LENGTH)) {
        fprintf(stderr, "Erreur de génération aléatoire\n");
        return 0;
    }

    // Dérive la clé
    unsigned char key[KEY_LENGTH];
    derive_key(password, salt, key);

    // Ouvre les fichiers
    FILE *in = fopen(input_path, "rb");
    FILE *out = fopen(output_path, "wb");
    if (!in || !out) {
        perror("Erreur d'ouverture de fichier");
        if (in) fclose(in);
        if (out) fclose(out);
        return 0;
    }

    // Écrit le sel et l'IV
    if (fwrite(salt, 1, SALT_LENGTH, out) != SALT_LENGTH ||
        fwrite(iv, 1, IV_LENGTH, out) != IV_LENGTH) {
        fprintf(stderr, "Erreur d'écriture des en-têtes\n");
        fclose(in);
        fclose(out);
        return 0;
    }

    // Initialise le chiffrement AES
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Erreur d'initialisation AES\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 0;
    }

    // Initialise le HMAC
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *hmac_ctx = EVP_MAC_CTX_new(hmac);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    if (!EVP_MAC_init(hmac_ctx, key, KEY_LENGTH, params)) {
        fprintf(stderr, "Erreur d'initialisation HMAC\n");
        EVP_MAC_CTX_free(hmac_ctx);
        EVP_MAC_free(hmac);
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 0;
    }

    // Chiffre le fichier par blocs
    unsigned char in_buf[BUFFER_SIZE], out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytes_read, out_len;
    int success = 1;

    while ((bytes_read = fread(in_buf, 1, BUFFER_SIZE, in)) > 0 && success) {
        if (!EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read) ||
            fwrite(out_buf, 1, out_len, out) != (size_t)out_len ||
            !EVP_MAC_update(hmac_ctx, out_buf, out_len)) {
            success = 0;
        }
    }

    // Finalise le chiffrement
    if (success && (!EVP_EncryptFinal_ex(ctx, out_buf, &out_len) ||
                   fwrite(out_buf, 1, out_len, out) != (size_t)out_len ||
                   !EVP_MAC_update(hmac_ctx, out_buf, out_len))) {
        success = 0;
    }

    // Calcule le HMAC final
    unsigned char hmac_value[HMAC_LENGTH];
    size_t hmac_len;
    if (success && (!EVP_MAC_final(hmac_ctx, hmac_value, &hmac_len, HMAC_LENGTH) ||
                   fwrite(hmac_value, 1, hmac_len, out) != hmac_len)) {
        success = 0;
    }

    // Crée le keystore
    if (success) {
        FILE *keystore = fopen("keystore.bin", "wb");
        if (keystore) {
            fwrite(salt, 1, SALT_LENGTH, keystore);
            fwrite(key, 1, KEY_LENGTH, keystore); // Stocke la clé pour vérification
            fwrite(hmac_value, 1, hmac_len, keystore);
            fclose(keystore);
        } else {
            perror("Avertissement: Impossible de créer keystore.bin");
        }
    }

    // Nettoie
    EVP_CIPHER_CTX_free(ctx);
    EVP_MAC_CTX_free(hmac_ctx);
    EVP_MAC_free(hmac);
    fclose(in);
    fclose(out);
    memset(key, 0, KEY_LENGTH);

    if (!success) {
        remove(output_path);
        fprintf(stderr, "Erreur lors du chiffrement\n");
        return 0;
    }

    return 1;
}

// Fonction de déchiffrement
int decrypt_file(const char *input_path, const char *output_path, const char *password) {
    // Vérifie que le fichier chiffré existe
    if (!file_exists(input_path)) {
        fprintf(stderr, "Erreur: Fichier chiffré introuvable\n");
        return 0;
    }

    // Vérifie que le keystore existe
    if (!file_exists("keystore.bin")) {
        fprintf(stderr, "Erreur: keystore.bin introuvable\n");
        return 0;
    }

    // Lit le keystore
    FILE *keystore = fopen("keystore.bin", "rb");
    if (!keystore) {
        perror("Erreur d'ouverture du keystore");
        return 0;
    }

    unsigned char salt[SALT_LENGTH], stored_key[KEY_LENGTH], stored_hmac[HMAC_LENGTH];
    if (fread(salt, 1, SALT_LENGTH, keystore) != SALT_LENGTH ||
        fread(stored_key, 1, KEY_LENGTH, keystore) != KEY_LENGTH ||
        fread(stored_hmac, 1, HMAC_LENGTH, keystore) != HMAC_LENGTH) {
        fprintf(stderr, "Erreur: keystore corrompu\n");
        fclose(keystore);
        return 0;
    }
    fclose(keystore);

    // Dérive la clé
    unsigned char derived_key[KEY_LENGTH];
    derive_key(password, salt, derived_key);

    // Vérifie le mot de passe
    if (memcmp(derived_key, stored_key, KEY_LENGTH) != 0) {
        printf("Mot de passe incorrect!\n");
        memset(derived_key, 0, KEY_LENGTH);
        return 0;
    }

    // Ouvre le fichier chiffré
    FILE *in = fopen(input_path, "rb");
    if (!in) {
        perror("Erreur d'ouverture du fichier chiffré");
        memset(derived_key, 0, KEY_LENGTH);
        return 0;
    }

    // Lit l'IV
    unsigned char iv[IV_LENGTH];
    if (fread(iv, 1, IV_LENGTH, in) != IV_LENGTH) {
        fprintf(stderr, "Erreur: Fichier chiffré corrompu (IV manquant)\n");
        fclose(in);
        memset(derived_key, 0, KEY_LENGTH);
        return 0;
    }

    // Initialise le déchiffrement AES
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived_key, iv)) {
        fprintf(stderr, "Erreur d'initialisation AES\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        memset(derived_key, 0, KEY_LENGTH);
        return 0;
    }

    // Initialise le HMAC
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *hmac_ctx = EVP_MAC_CTX_new(hmac);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    if (!EVP_MAC_init(hmac_ctx, derived_key, KEY_LENGTH, params)) {
        fprintf(stderr, "Erreur d'initialisation HMAC\n");
        EVP_MAC_CTX_free(hmac_ctx);
        EVP_MAC_free(hmac);
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        memset(derived_key, 0, KEY_LENGTH);
        return 0;
    }

    // Fichier temporaire pour le déchiffrement
    FILE *out = tmpfile();
    if (!out) {
        perror("Erreur de création du fichier temporaire");
        EVP_CIPHER_CTX_free(ctx);
        EVP_MAC_CTX_free(hmac_ctx);
        EVP_MAC_free(hmac);
        fclose(in);
        memset(derived_key, 0, KEY_LENGTH);
        return 0;
    }

    // Déchiffre par blocs
    unsigned char in_buf[BUFFER_SIZE], out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    long file_size;
    int bytes_read, out_len;
    int success = 1;

    fseek(in, 0, SEEK_END);
    file_size = ftell(in) - HMAC_LENGTH;
    fseek(in, SALT_LENGTH + IV_LENGTH, SEEK_SET);

    while (ftell(in) < file_size && success) {
        bytes_read = fread(in_buf, 1, BUFFER_SIZE, in);
        if (!EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, bytes_read) ||
            fwrite(out_buf, 1, out_len, out) != (size_t)out_len) {
            success = 0;
        }
        if (!EVP_MAC_update(hmac_ctx, in_buf, bytes_read)) {
            success = 0;
        }
    }

    // Finalise le déchiffrement
    if (success && (!EVP_DecryptFinal_ex(ctx, out_buf, &out_len) ||
                   fwrite(out_buf, 1, out_len, out) != (size_t)out_len)) {
        success = 0;
    }

    // Vérifie le HMAC
    unsigned char computed_hmac[HMAC_LENGTH];
    size_t hmac_len;
    if (success) {
        if (fread(in_buf, 1, HMAC_LENGTH, in) != HMAC_LENGTH ||
            !EVP_MAC_final(hmac_ctx, computed_hmac, &hmac_len, HMAC_LENGTH) ||
            hmac_len != HMAC_LENGTH || 
            CRYPTO_memcmp(stored_hmac, computed_hmac, HMAC_LENGTH) != 0) {
            success = 0;
            fprintf(stderr, "Erreur: Intégrité du fichier compromise\n");
        } else {
            printf("[+] Intégrité vérifiée avec succès\n");
        }
    }

    // Écrit le fichier final
    if (success) {
        rewind(out);
        FILE *final_out = fopen(output_path, "wb");
        if (final_out) {
            while ((bytes_read = fread(out_buf, 1, BUFFER_SIZE, out)) > 0) {
                fwrite(out_buf, 1, bytes_read, final_out);
            }
            fclose(final_out);
        } else {
            perror("Erreur de création du fichier de sortie");
            success = 0;
        }
    }

    // Nettoie
    EVP_CIPHER_CTX_free(ctx);
    EVP_MAC_CTX_free(hmac_ctx);
    EVP_MAC_free(hmac);
    fclose(in);
    fclose(out);
    memset(derived_key, 0, KEY_LENGTH);

    if (!success) {
        remove(output_path);
        return 0;
    }

    return 1;
}

// Menu principal
int main() {
    printf("\n=== Système de Chiffrement/Déchiffrement Sécurisé ===\n");
    printf("=== Utilise AES-256-CBC avec HMAC-SHA256 ===\n\n");

    int choice;
    char input_path[256], output_path[256];
    char password[256], verify_pwd[256];

    do {
        printf("\n1. Chiffrer un fichier\n");
        printf("2. Déchiffrer un fichier\n");
        printf("3. Quitter\n");
        printf("Choix : ");
        
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            printf("Entrée invalide. Veuillez réessayer.\n");
            continue;
        }
        getchar();

        if (choice == 3) break;

        printf("Fichier source : ");
        if (!fgets(input_path, sizeof(input_path), stdin)) {
            printf("Erreur de lecture\n");
            continue;
        }
        input_path[strcspn(input_path, "\n")] = 0;

        printf("Fichier destination : ");
        if (!fgets(output_path, sizeof(output_path), stdin)) {
            printf("Erreur de lecture\n");
            continue;
        }
        output_path[strcspn(output_path, "\n")] = 0;

        printf("Mot de passe : ");
        disable_echo();
        if (!fgets(password, sizeof(password), stdin)) {
            enable_echo();
            printf("\nErreur de lecture\n");
            continue;
        }
        enable_echo();
        printf("\n");
        password[strcspn(password, "\n")] = 0;

        // Vérification du mot de passe pour le chiffrement
        if (choice == 1) {
            printf("Confirmez le mot de passe : ");
            disable_echo();
            if (!fgets(verify_pwd, sizeof(verify_pwd), stdin)) {
                enable_echo();
                printf("\nErreur de lecture\n");
                continue;
            }
            enable_echo();
            printf("\n");
            verify_pwd[strcspn(verify_pwd, "\n")] = 0;

            if (strcmp(password, verify_pwd) != 0) {
                printf("Les mots de passe ne correspondent pas!\n");
                continue;
            }
        }

        switch (choice) {
            case 1:
                if (encrypt_file(input_path, output_path, password)) {
                    printf("[+] Chiffrement réussi!\n");
                    printf("[+] keystore.bin généré avec succès\n");
                } else {
                    printf("[-] Échec du chiffrement\n");
                }
                break;
            case 2:
                if (decrypt_file(input_path, output_path, password)) {
                    printf("[+] Déchiffrement réussi!\n");
                } else {
                    printf("[-] Échec du déchiffrement\n");
                }
                break;
            default:
                printf("Choix invalide\n");
        }
    } while (1);

    printf("\nAu revoir!\n");
    return 0;
}