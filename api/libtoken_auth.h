#ifndef __SMARTCARD_AUTH_TOKEN_H__
#define __SMARTCARD_AUTH_TOKEN_H__

#include "libtoken.h"

/****** Token operations **************/
/* Our authentication token specific instructions */
enum auth_token_instructions {
        /* This handles the encryption master key in AUTH mode */
        TOKEN_INS_GET_KEY   = 0x10,
        TOKEN_INS_GET_SDPWD = 0x11,
#ifdef FIDO_PROFILE
        /* Specific to the FIDO case */
        TOKEN_INS_FIDO_SEND_PKEY = 0x12,
        TOKEN_INS_FIDO_REGISTER = 0x13,
        TOKEN_INS_FIDO_AUTHENTICATE = 0x14,
        TOKEN_INS_FIDO_AUTHENTICATE_CHECK_ONLY = 0x15,
#endif
};

/* High level functions to communicate with the token */
int auth_token_get_key(token_channel *channel, const char *pin, unsigned int pin_len, unsigned char *key, unsigned int key_len, unsigned char *h_key, unsigned int h_key_len);

int auth_token_get_sdpwd(token_channel *channel, const char *pin, unsigned int pin_len, unsigned char *key, unsigned int key_len);

int auth_token_unlock_ops_exec(token_channel *channel, token_unlock_operations *ops, uint32_t num_ops, cb_token_callbacks *callbacks, databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num);

int auth_token_exchanges(token_channel *channel, cb_token_callbacks *callbacks, unsigned char *AES_CBC_ESSIV_key, unsigned int AES_CBC_ESSIV_key_len, unsigned char *AES_CBC_ESSIV_h_key, unsigned int AES_CBC_ESSIV_h_key_len, unsigned char *sdpwd, unsigned int sdpwd_len, databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num);

#ifdef FIDO_PROFILE
int auth_token_fido_send_pkey(token_channel *channel, const unsigned char *key, unsigned int key_len, const unsigned char *hmac, unsigned int hmac_len, unsigned char *hprivkey, unsigned int *hprivkey_len);

int auth_token_fido_register(token_channel *channel, const unsigned char *app_data, unsigned int app_data_len, unsigned char *key_handle, unsigned int *key_handle_len, unsigned char *ecdsa_priv_key, unsigned int *ecdsa_priv_key_len);

int auth_token_fido_authenticate(token_channel *channel, const unsigned char *app_data, unsigned int app_data_len, const unsigned char *key_handle, unsigned int key_handle_len, unsigned char *ecdsa_priv_key, unsigned int *ecdsa_priv_key_len, unsigned char check_only, bool *check_result);
#endif

#endif /* __SMARTCARD_AUTH_TOKEN_H__ */
