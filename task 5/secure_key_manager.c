#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define KEY_LENGTH 32 // 256 bits

// Fonction pour générer une clé aléatoire sécurisée
void generate_secure_key(unsigned char *key, size_t key_length) {
    if (RAND_bytes(key, key_length) != 1) {
        fprintf(stderr, "Erreur lors de la génération de la clé.\n");
        exit(EXIT_FAILURE);
    }
}

// Fonction pour stocker la clé dans un fichier protégé
void store_key_securely(const char *filename, const unsigned char *key, size_t key_length) {
    // Ouvrir le fichier avec des permissions restrictives
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("Erreur lors de l'ouverture du fichier pour écrire la clé");
        exit(EXIT_FAILURE);
    }

    // Écrire la clé dans le fichier
    if (write(fd, key, key_length) != key_length) {
        perror("Erreur lors de l'écriture de la clé dans le fichier");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
    printf("Clé stockée avec succès dans %s.\n", filename);
}

// Fonction principale
int main() {
    unsigned char key[KEY_LENGTH];

    // Générer une clé sécurisée
    generate_secure_key(key, KEY_LENGTH);
    printf("Clé générée : ");
    for (size_t i = 0; i < KEY_LENGTH; i++) {
        printf("%02x", key[i]); // Afficher la clé en hexadécimal
    }
    printf("\n");

    // Stocker la clé dans un fichier
    const char *filename = "secure_key.bin";
    store_key_securely(filename, key, KEY_LENGTH);

    return EXIT_SUCCESS;
}