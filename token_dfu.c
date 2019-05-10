#include "api/libtoken_dfu.h"
#include "libc/syscall.h"
#define SMARTCARD_DEBUG
#define MEASURE_TOKEN_PERF

#include "libc/stdio.h"
#include "libc/nostd.h"
#include "libc/string.h"

/* Include our encrypted platform keys  */
#include "DFU/encrypted_platform_dfu_keys.h"

#define SMARTCARD_DEBUG

/* Primitive for debug output */
#ifdef SMARTCARD_DEBUG
#define log_printf(...) printf(__VA_ARGS__)
#else
#define log_printf(...)
#endif

#define DERIVED_KEY_SIZE 16

static const unsigned char dfu_applet_AID[] = { 0x45, 0x75, 0x74, 0x77, 0x74, 0x75, 0x36, 0x41, 0x70, 0x71 };

/* Ask the DFU token to begin a decrypt session by sending a full header */
int dfu_token_begin_decrypt_session(token_channel *channel, const unsigned char *header, uint32_t header_len){
        SC_APDU_cmd apdu;
        SC_APDU_resp resp;

	/* Sanity checks */
	if((channel == NULL) || (header == NULL)){
		goto err;
	}
	/* Sanity checks on the size */
	if(header_len > (SHORT_APDU_LC_MAX - SHA256_DIGEST_SIZE)){
		goto err;
	}

        apdu.cla = 0x00; apdu.ins = TOKEN_INS_BEGIN_DECRYPT_SESSION; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = header_len; apdu.le = 0; apdu.send_le = 1;
	memcpy(apdu.data, header, header_len);
        if(token_send_receive(channel, &apdu, &resp)){
                goto err;
        }

        /******* Token response ***********************************/
        if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
                /* The smartcard responded an error */
                goto err_session;
        }

        return 0;
err_session:
	/* Notify that we had an explicit begin session error */
	return -2;
err:
        return -1;
}

/* Ask the DFU token to derive a session key for a firmware chunk */
int dfu_token_derive_key(token_channel *channel, unsigned char *derived_key, uint32_t derived_key_len, uint16_t num_chunk){
        SC_APDU_cmd apdu;
        SC_APDU_resp resp;

        /* Sanity checks */
        if((channel == NULL) || (derived_key == NULL)){
                goto err;
        }
	if(derived_key_len < DERIVED_KEY_SIZE){
		goto err;
	}

        apdu.cla = 0x00; apdu.ins = TOKEN_INS_DERIVE_KEY; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 2; apdu.le = DERIVED_KEY_SIZE; apdu.send_le = 1;
	apdu.data[0] = (num_chunk >> 8) & 0xff;
	apdu.data[1] = num_chunk & 0xff;
        if(token_send_receive(channel, &apdu, &resp)){
                goto err;
        }

        /******* Token response ***********************************/
        if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
                /* The smartcard responded an error */
                goto err;
        }
	/* Check the response */
	if(resp.le != DERIVED_KEY_SIZE){
		goto err;
	}
	memcpy(derived_key, resp.data, DERIVED_KEY_SIZE);

        return 0;
err:
        return -1;
}

int dfu_token_unlock_ops_exec(token_channel *channel, token_unlock_operations *ops, uint32_t num_ops, cb_token_callbacks *callbacks, unsigned char *decrypted_sig_pub_key_data, unsigned int *decrypted_sig_pub_key_data_len, databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num){
        if(token_unlock_ops_exec(channel, dfu_applet_AID, sizeof(dfu_applet_AID), keybag_dfu, sizeof(keybag_dfu)/sizeof(databag), PLATFORM_PBKDF2_ITERATIONS, USED_SIGNATURE_CURVE, ops, num_ops, callbacks, decrypted_sig_pub_key_data, decrypted_sig_pub_key_data_len, saved_decrypted_keybag, saved_decrypted_keybag_num)){
                goto err;
        }

        return 0;
err:
        return -1;
}

int dfu_token_exchanges(token_channel *channel, cb_token_callbacks *callbacks, unsigned char *decrypted_sig_pub_key_data, unsigned int *decrypted_sig_pub_key_data_len, databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num){
        /* Sanity checks */
        if(channel == NULL){
                goto err;
        }
	if(callbacks == NULL){
		goto err;
	}

        token_unlock_operations ops[] = { TOKEN_UNLOCK_INIT_TOKEN, TOKEN_UNLOCK_ASK_PET_PIN, TOKEN_UNLOCK_ESTABLISH_SECURE_CHANNEL, TOKEN_UNLOCK_PRESENT_PET_PIN, TOKEN_UNLOCK_CONFIRM_PET_NAME, TOKEN_UNLOCK_PRESENT_USER_PIN };
        if(dfu_token_unlock_ops_exec(channel, ops, sizeof(ops)/sizeof(token_unlock_operations), callbacks, decrypted_sig_pub_key_data, decrypted_sig_pub_key_data_len, saved_decrypted_keybag, saved_decrypted_keybag_num)){
                goto err;
        }

	return 0;

err:
        /* Zeroize token channel */
        token_zeroize_channel(channel);

	return -1;
}
