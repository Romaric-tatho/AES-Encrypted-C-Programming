#include"../encrypt.h"
#include <string.h>


// Fonction principale
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Utilisation : %s <fichier_a_crypter>\n", argv[0]);
        return 1;
    }

    const char *input_file = argv[1];
    unsigned char key[KEY_LENGTH];
    generate_key(key); // Générer une clé aléatoire

    // Créer le nom du fichier de sortie en remplaçant l'extension par .enc
    char output_file[256];
    snprintf(output_file, sizeof(output_file), "%.*s.enc", (int)(strrchr(input_file, '.') - input_file), input_file);
    
    encrypt_file(input_file, output_file, key);
    printf("Fichier crypté avec succès : %s\n", output_file);
    
    // Pour la démonstration, nous allons juste l'afficher en hexadécimal
    printf("Clé (hex) : ");
    for (int i = 0; i < KEY_LENGTH; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return 0;
}