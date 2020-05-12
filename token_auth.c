#include "api/libtoken_auth.h"
#include "wookey_ipc.h"

/* Include our encrypted platform keys  */
#include "AUTH/encrypted_platform_auth_keys.h"

#include "libc/syscall.h"
#include "libc/stdio.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/sanhandlers.h"

#define SMARTCARD_DEBUG
#define MEASURE_TOKEN_PERF

/* Primitive for debug output */
#ifdef SMARTCARD_DEBUG
#define log_printf(...) printf(__VA_ARGS__)
#else
#define log_printf(...)
#endif

static const unsigned char auth_applet_AID[] = { 0x45, 0x75, 0x74, 0x77, 0x74, 0x75, 0x36, 0x41, 0x70, 0x70 };

/* Get key and its derivative */
int auth_token_get_key(token_channel *channel, const char *pin, unsigned int pin_len, unsigned char *key, unsigned int key_len, unsigned char *h_key, unsigned int h_key_len){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;
	/* SHA256 context used to derive our secrets */
	sha256_context sha256_ctx;
	/* Digest buffer */
	uint8_t digest[SHA256_DIGEST_SIZE];
	/* AES context to decrypt the response */
	aes_context aes_context;
        uint8_t enc_IV[AES_BLOCK_SIZE];

	if((channel == NULL) || (channel->channel_initialized == 0)){
		goto err;
	}
	/* Sanity check */
	if((pin == NULL) || (key == NULL) || (h_key == NULL)){
		goto err;
	}
	/* Sanity checks on the key length and its derivative
	 * The Key is an AES-256 key, size is 32 bytes.
	 * The Key derivative is a SHA-256 of the key, i.e. 32 bytes.
	 */
	if((key_len != 32) || (h_key_len != SHA256_DIGEST_SIZE)){
		goto err;
	}

	memset(key, 0, key_len);
	memset(h_key, 0, h_key_len);

        /* Save the current IV and compute the AES-CBC IV (current IV incremented by 1) */
        memcpy(enc_IV, channel->IV, sizeof(enc_IV));
        add_iv(enc_IV, 1);

	apdu.cla = 0x00; apdu.ins = TOKEN_INS_GET_KEY; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = (key_len + h_key_len); apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
		/* The smartcard responded an error */
		goto err;
	}

	/* This is not the length we expect! */
	if(resp.le != (key_len + h_key_len)){
		goto err;
	}

	/* In order to avoid fault attacks on the token logics without providing a PIN, sensitive
	 * secrets are encrypted using a key derived from it.
	 * The KEY used here is a 128-bit AES key as the first half of SHA-256(first_IV || SHA-256(PIN)).
	 */
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, (const uint8_t*)pin, pin_len);
	sha256_final(&sha256_ctx, digest);

	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, channel->first_IV, sizeof(channel->first_IV));
	sha256_update(&sha256_ctx, digest, sizeof(digest));
	sha256_final(&sha256_ctx, digest);

	/* Decrypt our response buffer */
#if defined(__arm__)
	/* [RB] NOTE: we use a software masked AES for robustness against side channel attacks */
	if(aes_init(&aes_context, digest, AES128, enc_IV, CBC, AES_DECRYPT, PROTECTED_AES, NULL, NULL, -1, -1)){
#else
	/* [RB] NOTE: if not on our ARM target, we use regular portable implementation for simulations */
	if(aes_init(&aes_context, digest, AES128, enc_IV, CBC, AES_DECRYPT, AES_SOFT_UNMASKED, NULL, NULL, -1, -1)){
#endif
		goto err;
	}
	/* Decrypt */
	if(aes_exec(&aes_context, resp.data, resp.data, resp.le, -1, -1)){
		goto err;
	}

	/* Now split the response */
	memcpy(key, resp.data, key_len);
	memcpy(h_key, resp.data + key_len, h_key_len);

	return 0;
err:
	return -1;

}

static cb_token_request_pin_t external_request_pin = NULL;
static char saved_user_pin[32] = { 0 };
static char saved_user_pin_len = 0;
static int local_request_pin(char *pin, unsigned int *pin_len, token_pin_types pin_type, token_pin_actions action){
	if(external_request_pin == NULL){
		goto err;
	}
	if(handler_sanity_check((void*)external_request_pin)){
		sys_exit();
		goto err;
	}
	external_request_pin(pin, pin_len, pin_type, action);
	if((pin_type == TOKEN_USER_PIN) && (action == TOKEN_PIN_AUTHENTICATE)){
		/* Save the PIN for later */
		if(*pin_len <= sizeof(saved_user_pin)){
			memcpy(saved_user_pin, pin, *pin_len);
			saved_user_pin_len = *pin_len;
		}
		else{
			goto err;
		}
	}

	return 0;

err:
	return -1;
}
/* Register callback */
ADD_GLOB_HANDLER(local_request_pin)

int auth_token_unlock_ops_exec(token_channel *channel, token_unlock_operations *ops, uint32_t num_ops, cb_token_callbacks *callbacks, databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num){
	if(token_unlock_ops_exec(channel, auth_applet_AID, sizeof(auth_applet_AID), keybag_auth, sizeof(keybag_auth)/sizeof(databag), PLATFORM_PBKDF2_ITERATIONS, USED_SIGNATURE_CURVE, ops, num_ops, callbacks, NULL, NULL, saved_decrypted_keybag, saved_decrypted_keybag_num)){
		goto err;
	}

	return 0;
err:
	return -1;
}

/* We provide two callbacks: one to ask for the PET pin, the other to
 * ask for the user PIN while showing the PET name to get confirmation.
 */
int auth_token_exchanges(token_channel *channel, cb_token_callbacks *callbacks, unsigned char *AES_CBC_ESSIV_key, unsigned int AES_CBC_ESSIV_key_len, unsigned char *AES_CBC_ESSIV_h_key, unsigned int AES_CBC_ESSIV_h_key_len, databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num){
	/* Sanity checks */
	if(channel == NULL){
		goto err;
	}
	if((AES_CBC_ESSIV_key == NULL) || (AES_CBC_ESSIV_h_key == NULL)){
		goto err;
	}
	if((AES_CBC_ESSIV_key_len != 32) || (AES_CBC_ESSIV_h_key_len != 32)){
		goto err;
	}
	if(callbacks == NULL){
		goto err;
	}

	cb_token_callbacks local_callbacks = (*callbacks);
	external_request_pin = callbacks->request_pin;
	local_callbacks.request_pin = local_request_pin;
	token_unlock_operations ops[] = { TOKEN_UNLOCK_INIT_TOKEN, TOKEN_UNLOCK_ASK_PET_PIN, TOKEN_UNLOCK_ESTABLISH_SECURE_CHANNEL, TOKEN_UNLOCK_PRESENT_PET_PIN, TOKEN_UNLOCK_CONFIRM_PET_NAME, TOKEN_UNLOCK_PRESENT_USER_PIN };
	if(auth_token_unlock_ops_exec(channel, ops, sizeof(ops)/sizeof(token_unlock_operations), &local_callbacks, saved_decrypted_keybag, saved_decrypted_keybag_num)){
		goto err;
	}
	/*************** Get the CBC-ESSIV key and its hash */
	if(auth_token_get_key(channel, saved_user_pin, saved_user_pin_len, AES_CBC_ESSIV_key, AES_CBC_ESSIV_key_len, AES_CBC_ESSIV_h_key, AES_CBC_ESSIV_h_key_len)){
		goto err;
	}

	return 0;

err:
        /* Zeroize token channel */
	token_zeroize_channel(channel);

	return -1;
}
