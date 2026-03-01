/**
 * HSM Wrapper — Secure Key Operations
 * 
 * This module exposes cryptographic operations performed inside an HSM
 * (Hardware Security Module) or cloud KMS. Keys NEVER leave the HSM.
 * 
 * In production:
 *  - Link against the vendor HSM SDK (e.g. Thales Luna, AWS CloudHSM)
 *  - All signing/encryption is performed inside the HSM hardware
 *  - This C code is compiled and exposed via FFI to Java and Rust
 * 
 * PCI Scope: This component is IN SCOPE for PCI DSS.
 * Access to this repository MUST be restricted with tighter controls.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ============================================================
 * HSM Session Management
 * ============================================================ */

typedef struct {
    int session_id;
    int is_authenticated;
    char slot_label[64];
} HSMSession;

/**
 * Initialize HSM session.
 * In production: calls CK_C_Initialize() and CK_C_OpenSession() from PKCS#11.
 */
HSMSession* hsm_init(const char* slot_label, const char* pin) {
    HSMSession* session = (HSMSession*)malloc(sizeof(HSMSession));
    if (!session) {
        fprintf(stderr, "[HSM] Failed to allocate session\n");
        return NULL;
    }

    session->session_id = 1; // Simulated session ID
    session->is_authenticated = 0;
    strncpy(session->slot_label, slot_label, sizeof(session->slot_label) - 1);
    session->slot_label[sizeof(session->slot_label) - 1] = '\0';

    /* In production: CK_C_Login(session, CKU_USER, pin, pin_len) */
    if (pin != NULL && strlen(pin) > 0) {
        session->is_authenticated = 1;
        printf("[HSM] Session authenticated for slot: %s\n", slot_label);
    }

    return session;
}

/**
 * Close HSM session and free resources.
 */
void hsm_close(HSMSession* session) {
    if (session) {
        printf("[HSM] Closing session %d for slot: %s\n", session->session_id, session->slot_label);
        /* In production: CK_C_CloseSession(session->session_id) */
        free(session);
    }
}

/* ============================================================
 * Signing Operations (keys stay inside HSM)
 * ============================================================ */

/**
 * Sign data using a key stored in the HSM.
 * The private key NEVER leaves the HSM boundary.
 * 
 * @param session  Active HSM session
 * @param key_label Label of the signing key in the HSM
 * @param data     Data to sign
 * @param data_len Length of data
 * @param sig_out  Output buffer for signature
 * @param sig_len  Output: actual signature length
 * @return 0 on success, -1 on error
 */
int hsm_sign(HSMSession* session, const char* key_label,
             const uint8_t* data, size_t data_len,
             uint8_t* sig_out, size_t* sig_len) {
    if (!session || !session->is_authenticated) {
        fprintf(stderr, "[HSM] Session not authenticated\n");
        return -1;
    }

    /* In production:
     * CK_C_SignInit(session, &mechanism, key_handle)
     * CK_C_Sign(session, data, data_len, sig_out, sig_len)
     */

    /* Simulated signature (placeholder) */
    const char* sim_sig = "SIMULATED_HSM_SIGNATURE";
    size_t sim_len = strlen(sim_sig);
    
    if (*sig_len < sim_len) {
        fprintf(stderr, "[HSM] Signature buffer too small\n");
        return -1;
    }

    memcpy(sig_out, sim_sig, sim_len);
    *sig_len = sim_len;

    printf("[HSM] Signed %zu bytes with key '%s'\n", data_len, key_label);
    return 0;
}

/* ============================================================
 * Key Generation (inside HSM hardware)
 * ============================================================ */

/**
 * Generate a new signing key pair inside the HSM.
 * The private key component NEVER leaves the HSM.
 * 
 * @param session   Active HSM session
 * @param key_label Label to assign to the new key
 * @return 0 on success, -1 on error
 */
int hsm_generate_key(HSMSession* session, const char* key_label) {
    if (!session || !session->is_authenticated) {
        fprintf(stderr, "[HSM] Session not authenticated\n");
        return -1;
    }

    /* In production:
     * CK_C_GenerateKeyPair(session, &mechanism, pub_template, priv_template, ...)
     */

    printf("[HSM] Key pair generated with label: %s\n", key_label);
    return 0;
}

/* ============================================================
 * Encryption/Decryption
 * ============================================================ */

/**
 * Encrypt data using an HSM-managed key.
 */
int hsm_encrypt(HSMSession* session, const char* key_label,
                const uint8_t* plaintext, size_t pt_len,
                uint8_t* ciphertext_out, size_t* ct_len) {
    if (!session || !session->is_authenticated) {
        return -1;
    }

    /* In production: CK_C_EncryptInit + CK_C_Encrypt */
    
    /* Simulated: XOR with 0xFF (placeholder only) */
    if (*ct_len < pt_len) return -1;
    for (size_t i = 0; i < pt_len; i++) {
        ciphertext_out[i] = plaintext[i] ^ 0xFF;
    }
    *ct_len = pt_len;

    printf("[HSM] Encrypted %zu bytes with key '%s'\n", pt_len, key_label);
    return 0;
}

/**
 * Decrypt data using an HSM-managed key.
 */
int hsm_decrypt(HSMSession* session, const char* key_label,
                const uint8_t* ciphertext, size_t ct_len,
                uint8_t* plaintext_out, size_t* pt_len) {
    if (!session || !session->is_authenticated) {
        return -1;
    }

    /* In production: CK_C_DecryptInit + CK_C_Decrypt */
    
    if (*pt_len < ct_len) return -1;
    for (size_t i = 0; i < ct_len; i++) {
        plaintext_out[i] = ciphertext[i] ^ 0xFF;
    }
    *pt_len = ct_len;

    printf("[HSM] Decrypted %zu bytes with key '%s'\n", ct_len, key_label);
    return 0;
}

/* ============================================================
 * Key Rotation
 * ============================================================ */

/**
 * Rotate a signing key: generate new key, mark old as deprecated.
 * In production: implement key versioning and graceful migration.
 */
int hsm_rotate_key(HSMSession* session, const char* current_label, const char* new_label) {
    if (!session || !session->is_authenticated) {
        return -1;
    }

    int ret = hsm_generate_key(session, new_label);
    if (ret != 0) {
        fprintf(stderr, "[HSM] Key rotation failed: could not generate new key\n");
        return -1;
    }

    printf("[HSM] Key rotated: %s -> %s\n", current_label, new_label);
    return 0;
}
