#ifndef __SMARTCARD_DFU_TOKEN_H__
#define __SMARTCARD_DFU_TOKEN_H__

#include "libtoken.h"

/****** Token operations **************/
/* Our dfuentication token specific instructions */
enum dfu_token_instructions {
        /* This handles firmware encryption key derivation in DFU mode */
        TOKEN_INS_BEGIN_DECRYPT_SESSION = 0x20,
        TOKEN_INS_DERIVE_KEY = 0x21,
};

/* High level functions to communicate with the token */
int dfu_token_begin_decrypt_session(token_channel *channel, const unsigned char *iv, uint32_t iv_len, const unsigned char *iv_hmac, uint32_t iv_hmac_len);
int dfu_token_derive_key(token_channel *channel, unsigned char *derived_key, uint32_t derived_key_len);

int dfu_token_unlock_ops_exec(token_channel *channel, token_unlock_operations *ops, uint32_t num_ops, cb_token_callbacks *callbacks, unsigned char *decrypted_sig_pub_key_data, unsigned int *decrypted_sig_pub_key_data_len);

int dfu_token_exchanges(token_channel *channel, cb_token_callbacks *callbacks, unsigned char *decrypted_sig_pub_key_data, unsigned int *decrypted_sig_pub_key_data_len);

#endif /* __SMARTCARD_DFU_TOKEN_H__ */
