#include <stdio.h>
#include <string.h>
#include "hsm_wrapper.h"

int main(int argc, char* argv[]) {
    printf("--- WarmHeart HSM CLI ---\n");

    HSMSession* session = hsm_init("SLOT_0", "1234");
    if (!session) {
        return 1;
    }

    const char* data = "Hello, Secure World!";
    uint8_t sig[256];
    size_t sig_len = sizeof(sig);

    if (hsm_sign(session, "signing-key-1", (uint8_t*)data, strlen(data), sig, &sig_len) == 0) {
        printf("Successfully signed data using HSM. Sig Length: %zu\n", sig_len);
    }

    hsm_close(session);
    printf("--- HSM Operation Complete ---\n");
    return 0;
}
