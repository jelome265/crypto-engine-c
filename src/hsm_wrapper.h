#ifndef HSM_WRAPPER_H
#define HSM_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    int session_id;
    int is_authenticated;
    char slot_label[64];
} HSMSession;

/* Session management */
HSMSession* hsm_init(const char* slot_label, const char* pin);
void hsm_close(HSMSession* session);

/* Signing (key stays inside HSM) */
int hsm_sign(HSMSession* session, const char* key_label,
             const uint8_t* data, size_t data_len,
             uint8_t* sig_out, size_t* sig_len);

/* Key generation */
int hsm_generate_key(HSMSession* session, const char* key_label);

/* Encryption/Decryption */
int hsm_encrypt(HSMSession* session, const char* key_label,
                const uint8_t* plaintext, size_t pt_len,
                uint8_t* ciphertext_out, size_t* ct_len);

int hsm_decrypt(HSMSession* session, const char* key_label,
                const uint8_t* ciphertext, size_t ct_len,
                uint8_t* plaintext_out, size_t* pt_len);

/* Key rotation */
int hsm_rotate_key(HSMSession* session, const char* current_label, const char* new_label);

#endif /* HSM_WRAPPER_H */
