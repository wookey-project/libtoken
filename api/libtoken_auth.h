#ifndef __SMARTCARD_AUTH_TOKEN_H__
#define __SMARTCARD_AUTH_TOKEN_H__

#include "libtoken.h"

/****** Token operations **************/
/* Our authentication token specific instructions */
enum auth_token_instructions {
        /* This handles the encryption master key in AUTH mode */
        TOKEN_INS_GET_KEY = 0x10,
};

/* High level functions to communicate with the token */
int auth_token_get_key(token_channel *channel, const char *pin, unsigned int pin_len, unsigned char *key, unsigned int key_len, unsigned char *h_key, unsigned int h_key_len);

int auth_token_unlock_ops_exec(token_channel *channel, token_unlock_operations *ops, uint32_t num_ops, cb_token_callbacks *callbacks);

int auth_token_exchanges(token_channel *channel, cb_token_callbacks *callbacks, unsigned char *AES_CBC_ESSIV_key, unsigned int AES_CBC_ESSIV_key_len, unsigned char *AES_CBC_ESSIV_h_key, unsigned int AES_CBC_ESSIV_h_key_len);

#endif /* __SMARTCARD_AUTH_TOKEN_H__ */
