#ifndef DECRYPT_H
#define DECRYPT_H

#include <stdio.h>
#include <openssl/evp.h>

#define KEY_LENGTH 32 // Longueur de la clé pour AES-256
#define IV_LENGTH 16  // Longueur du vecteur d'initialisation pour AES
#define BUFFER_SIZE 1024

// Prototypes des fonctions
void hex_to_bytes(const char *hex, unsigned char *bytes);
int decrypt_file(const char *input_file, const char *output_file, const unsigned char *key);

#endif // DECRYPT_H