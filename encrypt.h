#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stdio.h>
#include <openssl/evp.h>

#define KEY_LENGTH 32 // Longueur de la clé pour AES-256
#define IV_LENGTH 16  // Longueur du vecteur d'initialisation pour AES
#define BUFFER_SIZE 1024

// Prototypes des fonctions
void encrypt_file(const char *input_file, const char *output_file, const unsigned char *key);
void generate_key(unsigned char *key);

#endif // ENCRYPT_H