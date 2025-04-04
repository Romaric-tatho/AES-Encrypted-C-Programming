#include"../decrypt.h"


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