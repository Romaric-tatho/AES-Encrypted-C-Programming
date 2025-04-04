#ifndef KEY_DERIVATION_FUNCTION_H
#define KEY_DERIVATION_FUNCTION_H

// #include <stdio.h>
// #include <openssl/evp.h>

#define KEY_LENGTH 32 // Longueur de la clé pour AES-256
#define IV_LENGTH 16  // Longueur du vecteur d'initialisation pour AES
#define BUFFER_SIZE 1024

// Prototypes des fonctions
void generate_salt(unsigned char *salt);
void derive_key(const char *password, unsigned char *salt, unsigned char *key);
void store_key(const char *filename, unsigned char *salt, unsigned char *key);

#endif // KEY-DERIVATION-FUNCTION_H