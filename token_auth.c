#include "api/libtoken_auth.h"
#include "wookey_ipc.h"

/* Include our encrypted platform keys  */
#include "AUTH/encrypted_platform_auth_keys.h"

#include "libc/syscall.h"
#include "libc/stdio.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/sanhandlers.h"

#ifdef FIDO_PROFILE
/* Specific to the FIDO platform case */
#include "libfido.h"
#endif

#define SMARTCARD_DEBUG
#define MEASURE_TOKEN_PERF

/* Primitive for debug output */
#ifdef SMARTCARD_DEBUG
#define log_printf(...) printf(__VA_ARGS__)
#else
#define log_printf(...)
#endif

static const unsigned char auth_applet_AID[] = { 0x45, 0x75, 0x74, 0x77, 0x74, 0x75, 0x36, 0x41, 0x70, 0x70 };

/* Get SDCard passwd  */
int auth_token_get_sdpwd(token_channel *channel, const char *pin, unsigned int pin_len, unsigned char *sdpwd, unsigned int sdpwd_len){
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
	if((pin == NULL) || (sdpwd == NULL)){
		goto err;
	}
	/* Sanity checks on the key length and its derivative
	 * The password can be upto 16 chars, size is 16 bytes.
	 */
	if(sdpwd_len != 16){
                printf("%s : %d wrong key len %d\n", __FILE__, __LINE__, sdpwd_len);
		goto err;
	}

	memset(sdpwd, 0, sdpwd_len);

        /* Save the current IV and compute the AES-CBC IV (current IV incremented by 1) */
        memcpy(enc_IV, channel->IV, sizeof(enc_IV));
        add_iv(enc_IV, 1); /* Mandatory increment by one even if Lc = 0 */

	apdu.cla = 0x00; apdu.ins = TOKEN_INS_GET_SDPWD; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = sdpwd_len; apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
                printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
                printf("%s : %d sw1 %x sw2 %x\n",__FILE__,__LINE__, resp.sw1, resp.sw2);
                printf("%s : %d\n",__FILE__,__LINE__);
		/* The smartcard responded an error */
		goto err;
	}

	/* This is not the length we expect! */
        if(resp.le != sdpwd_len){
                printf("resp. len: resp.le: %d\n", resp.le);
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
                printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	/* Decrypt */
	if(aes_exec(&aes_context, resp.data, resp.data, resp.le, -1, -1)){
                printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

        memcpy(sdpwd, resp.data, sdpwd_len);

	return 0;
err:
	return -1;
}




/* Get master key and its derivative */
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
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	/* Sanity check */
	if((pin == NULL) || (key == NULL) || (h_key == NULL)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	/* Sanity checks on the key length and its derivative
	 * The Key is an AES-256 key, size is 32 bytes.
	 * The Key derivative is a SHA-256 of the key, i.e. 32 bytes.
	 */
	if((key_len != 32) || (h_key_len != SHA256_DIGEST_SIZE)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	memset(key, 0, key_len);
	memset(h_key, 0, h_key_len);

        /* Save the current IV and compute the AES-CBC IV (current IV incremented by 1) */
        memcpy(enc_IV, channel->IV, sizeof(enc_IV));
        add_iv(enc_IV, 1); /* Mandatory increment by one even if Lc = 0 */

	apdu.cla = 0x00; apdu.ins = TOKEN_INS_GET_KEY; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = (key_len + h_key_len); apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
                 printf("%s : %d\n",__FILE__,__LINE__);
		/* The smartcard responded an error */
		goto err;
	}

	/* This is not the length we expect! */
	if(resp.le != (key_len + h_key_len)){
                printf("%s : %d\n",__FILE__,__LINE__);
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
                printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	/* Decrypt */
	if(aes_exec(&aes_context, resp.data, resp.data, resp.le, -1, -1)){
                printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	/* Now split the response */
	memcpy(key, resp.data, key_len);
	memcpy(h_key, resp.data + key_len, h_key_len);

	return 0;
err:
	return -1;
}

/*************************************************************************************/
/*************************************************************************************/
/*************************************************************************************/
/*************************************************************************************/
static cb_token_request_pin_t external_request_pin = NULL;
static char saved_user_pin[32] = { 0 };
static char saved_user_pin_len = 0;
static int local_request_pin(char *pin, unsigned int *pin_len, token_pin_types pin_type, token_pin_actions action){
	if(external_request_pin == NULL){
		goto err;
	}
	if(handler_sanity_check_with_panic((physaddr_t)external_request_pin)){
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
int auth_token_exchanges(token_channel *channel, cb_token_callbacks *callbacks, unsigned char *MASTER_key, unsigned int MASTER_key_len, unsigned char *MASTER_h_key, unsigned int MASTER_h_key_len, unsigned char *sdpwd, unsigned int sdpwd_len, databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num){
	/* Sanity checks */
	if(channel == NULL){
		goto err;
	}
	if((MASTER_key == NULL) || (MASTER_h_key == NULL)){
		goto err;
	}
	if((MASTER_key_len != 32) || (MASTER_h_key_len != 32)){
		goto err;
	}
	if(sdpwd == NULL){
		goto err;
	}
	if(sdpwd_len != 16){
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
	/*************** Get the master key and its hash */
	if(auth_token_get_key(channel, saved_user_pin, saved_user_pin_len, MASTER_key, MASTER_key_len, MASTER_h_key, MASTER_h_key_len)){
		goto err;
	}
	/*************** Get the SD card locking/unlocking password */
        if(auth_token_get_sdpwd(channel, saved_user_pin, saved_user_pin_len, sdpwd, sdpwd_len)){
		goto err;
        }
         
	return 0;

err:
        /* Zeroize token channel */
	token_zeroize_channel(channel);

	return -1;
}


/********* FIDO token specific commands **********************************/
/*************************************************************************/
#ifdef FIDO_PROFILE

/* Only for FIDO tokens. Send our local platform key secret for key handles computation.
 */
int auth_token_fido_send_pkey(token_channel *channel, const unsigned char *key, unsigned int key_len, const unsigned char *hmac, unsigned int hmac_len, unsigned char *hprivkey, unsigned int *hprivkey_len){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;
	/* SHA256 context used to derive our secrets */
	sha256_context sha256_ctx;
	/* Digest buffer */
	uint8_t digest[SHA256_DIGEST_SIZE];
	/* AES context to encrypt the half key */
	aes_context aes_context;
        uint8_t enc_IV[AES_BLOCK_SIZE];

	if((channel == NULL) || (channel->channel_initialized == 0)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	/* Sanity check */
	if((key == NULL) || (hmac == NULL) || (hprivkey == NULL) || (hprivkey_len == NULL)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	/* In order to avoid fault attacks on the token logics without providing a PIN, sensitive
	 * secrets are encrypted using a key derived from it.
	 * The KEY used here is a 128-bit AES key as the first half of SHA-256(first_IV || SHA-256(PIN)).
	 */
        if(saved_user_pin_len > sizeof(saved_user_pin)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
        }

	/* Check HMAC SHA-256 length */
	if(hmac_len != SHA256_DIGEST_SIZE){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err; 
	}
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, (const uint8_t*)saved_user_pin, saved_user_pin_len);
	sha256_final(&sha256_ctx, digest);

	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, channel->first_IV, sizeof(channel->first_IV));
	sha256_update(&sha256_ctx, digest, sizeof(digest));
	sha256_final(&sha256_ctx, digest);

	/* Sanity check on the platform key length */
	if((key_len + hmac_len) > (SHORT_APDU_LE_MAX - SHA256_DIGEST_SIZE)){
        	printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	/* Copy IV */
        memcpy(enc_IV, channel->IV, sizeof(enc_IV));
	/* Encrypt our command buffer */
#if defined(__arm__)
	/* [RB] NOTE: we use a software masked AES for robustness against side channel attacks */
	if(aes_init(&aes_context, digest, AES128, enc_IV, CBC, AES_ENCRYPT, PROTECTED_AES, NULL, NULL, -1, -1)){
#else
	/* [RB] NOTE: if not on our ARM target, we use regular portable implementation for simulations */
	if(aes_init(&aes_context, digest, AES128, enc_IV, CBC, AES_ENCRYPT, AES_SOFT_UNMASKED, NULL, NULL, -1, -1)){
#endif
                printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	/* Encrypt */
	memcpy(&apdu.data[0], key, key_len);
	memcpy(&apdu.data[key_len], hmac, hmac_len);
	if(aes_exec(&aes_context, apdu.data, apdu.data, (key_len + hmac_len), -1, -1)){
                printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	apdu.cla = 0x00; apdu.ins = TOKEN_INS_FIDO_SEND_PKEY; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = (key_len + hmac_len); apdu.le = 0; apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
                 printf("%s : %d\n",__FILE__,__LINE__);
		/* The smartcard responded an error */
		goto err;
	}

	/* This is not the length we expect! */
	if(resp.le != 16){
                printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	/* We get back the half private FIDO key */
	if(*hprivkey_len < 16){
                printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	/* Compute the AES-CBC IV (current IV incremented by some blocks and 1) */
        add_iv(enc_IV, 1 + ((key_len + hmac_len) / AES_BLOCK_SIZE)); /* 4 AES blocks sent + one mandatory increment */
	/* Decrypt sensitive data */
	/* In order to avoid fault attacks on the token logics without providing a PIN, sensitive
	 * secrets are encrypted using a key derived from it.
	 * The KEY used here is a 128-bit AES key as the first half of SHA-256(first_IV || SHA-256(PIN)).
	 */
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, (const uint8_t*)saved_user_pin, saved_user_pin_len);
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
                printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	/* Decrypt */
	if(aes_exec(&aes_context, resp.data, hprivkey, resp.le, -1, -1)){
                printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	*hprivkey_len = 16;

	return 0;
err:
	if(hprivkey_len != NULL){
		*hprivkey_len = 0;
	}
	return -1;

}

/* Only for FIDO tokens. FIDO REGISTER.
 */
int auth_token_fido_register(token_channel *channel, const unsigned char *app_data, unsigned int app_data_len, unsigned char *key_handle, unsigned int *key_handle_len, unsigned char *ecdsa_priv_key, unsigned int *ecdsa_priv_key_len){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;

	if((channel == NULL) || (channel->channel_initialized == 0)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	/* Sanity check */
	if((app_data == NULL) || (key_handle == NULL) || (key_handle_len == NULL) || (ecdsa_priv_key_len == NULL)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	/* Sanity checks on the lengths.
	 */
	if(app_data_len != FIDO_APPLICATION_PARAMETER_SIZE){
        	printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

        /* Copy elements */
        if(FIDO_APPLICATION_PARAMETER_SIZE > (SHORT_APDU_LC_MAX - SHA256_DIGEST_SIZE)){
        	printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
        }
        memcpy(apdu.data, app_data, FIDO_APPLICATION_PARAMETER_SIZE);
	apdu.cla = 0x00; apdu.ins = TOKEN_INS_FIDO_REGISTER; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = FIDO_APPLICATION_PARAMETER_SIZE; apdu.le = 0; apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
                 printf("%s : %d\n",__FILE__,__LINE__);
		/* The smartcard responded an error */
		goto err;
	}

	/* This is not the length we expect! */
	if(resp.le != (FIDO_KEY_HANDLE_SIZE + FIDO_PRIV_KEY_SIZE)){
                printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	/* Now copy the response */
	if(*key_handle_len < FIDO_KEY_HANDLE_SIZE){
	        printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	*key_handle_len = FIDO_KEY_HANDLE_SIZE;
	memcpy(key_handle, resp.data, FIDO_KEY_HANDLE_SIZE);
	/**/
	if(*ecdsa_priv_key_len < FIDO_PRIV_KEY_SIZE){
	        printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	*ecdsa_priv_key_len = FIDO_PRIV_KEY_SIZE;
	memcpy(ecdsa_priv_key, resp.data + FIDO_KEY_HANDLE_SIZE, FIDO_PRIV_KEY_SIZE);

	return 0;
err:
	if(key_handle_len != NULL){
		*key_handle_len = 0;
	}
	if(ecdsa_priv_key_len != NULL){
		*ecdsa_priv_key_len = 0;
	}
	return -1;

}

/* Only for FIDO tokens. FIDO AUTHENTICATE.
 */
int auth_token_fido_authenticate(token_channel *channel, const unsigned char *app_data, unsigned int app_data_len, const unsigned char *key_handle, unsigned int key_handle_len, unsigned char *ecdsa_priv_key, unsigned int *ecdsa_priv_key_len, unsigned char check_only, bool *check_result){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;

	if((channel == NULL) || (channel->channel_initialized == 0)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	/* Sanity check */
	if((app_data == NULL) || (key_handle == NULL) || (check_result == NULL)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	*check_result = false;
	if(check_only == 0){
		if((ecdsa_priv_key == NULL) || (ecdsa_priv_key_len == NULL)){
        	  printf("%s : %d\n",__FILE__,__LINE__);
			goto err;
		}
	}
	if(check_only != 0){
		apdu.ins = TOKEN_INS_FIDO_AUTHENTICATE_CHECK_ONLY;
	}
	else{
		apdu.ins = TOKEN_INS_FIDO_AUTHENTICATE;
	}

	/* Copy input */
	if(app_data_len != FIDO_APPLICATION_PARAMETER_SIZE){
        	printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
        if(app_data_len > (SHORT_APDU_LC_MAX - SHA256_DIGEST_SIZE)){
        	printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
        }
        memcpy(apdu.data, app_data, FIDO_APPLICATION_PARAMETER_SIZE);
	if(key_handle_len != FIDO_KEY_HANDLE_SIZE){
        	printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
        if(key_handle_len > (SHORT_APDU_LC_MAX - SHA256_DIGEST_SIZE - FIDO_APPLICATION_PARAMETER_SIZE)){
        	printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
        }
        memcpy(apdu.data + FIDO_APPLICATION_PARAMETER_SIZE, key_handle, FIDO_KEY_HANDLE_SIZE);
	apdu.cla = 0x00; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = (FIDO_APPLICATION_PARAMETER_SIZE + FIDO_KEY_HANDLE_SIZE); apdu.le = 0; apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
                 printf("%s : %d\n",__FILE__,__LINE__);
		/* The smartcard responded an error */
		goto err;
	}

	if(check_only != 0){
		if(resp.le != 1){
                 	printf("%s : %d\n",__FILE__,__LINE__);
			goto err;
		}
		if(resp.data[0] != 0x01){
			/* Key handle check failed */
			*check_result = false;
		}
		else{
			/* Key handle check is OK */
			*check_result = true;
		}
		/* If we are in check only mode, this is it, check succeeded! */
		if(ecdsa_priv_key_len != NULL){
			*ecdsa_priv_key_len = 0;
		}
	}
	else{
		/* Not check only mode, get back the private key if possible */
		if(resp.le == 1){
			if(resp.data[0] != 0x00){
                 		printf("%s : %d\n",__FILE__,__LINE__);
				goto err;
			}
			/* Key handle check failed ... */
			*check_result = false;
		}
		else{
			/* This is not the length we expect! */
			if(resp.le != FIDO_PRIV_KEY_SIZE){
        		        printf("%s : %d\n",__FILE__,__LINE__);
				goto err;
			}
			/* Now copy the response */
			/**/
			if(*ecdsa_priv_key_len < FIDO_PRIV_KEY_SIZE){
	        		printf("%s : %d\n",__FILE__,__LINE__);
				goto err;
			}
			*check_result = true;
			*ecdsa_priv_key_len = FIDO_PRIV_KEY_SIZE;
			memcpy(ecdsa_priv_key, resp.data, FIDO_PRIV_KEY_SIZE);
		}
	}
	return 0;
err:
	if(check_result != NULL){
		*check_result = false;
	}
	if(ecdsa_priv_key_len != NULL){
		*ecdsa_priv_key_len = 0;
	}
	return -1;

}

/* Only for FIDO tokens. Get our anti-replay counter.
 */
int auth_token_fido_get_replay_counter(token_channel *channel, unsigned char *counter, unsigned int *counter_len){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;

	if((channel == NULL) || (channel->channel_initialized == 0)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	/* Sanity check */
	if((counter == NULL) || (counter_len == NULL)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	

	apdu.ins = TOKEN_INS_FIDO_GET_REPLAY_COUNTER;
	apdu.cla = 0x00; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = (*counter_len); apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
                 printf("%s : %d\n",__FILE__,__LINE__);
		/* The smartcard responded an error */
		goto err;
	}
	if(resp.le > *counter_len){
		goto err;
	}
	*counter_len = resp.le;
	memcpy(counter, resp.data, resp.le);

	return 0;
err:
	if(counter_len != NULL){
		*counter_len = 0;
	}
	return -1;
}

/* Only for FIDO tokens. Set our anti-replay counter.
 */
int auth_token_fido_set_replay_counter(token_channel *channel, const unsigned char *counter, unsigned int counter_len){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;

	if((channel == NULL) || (channel->channel_initialized == 0)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	/* Sanity check */
	if(counter == NULL){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	/* Sanity check */
	if(counter_len > (SHORT_APDU_LC_MAX - SHA256_DIGEST_SIZE)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}
	memcpy(apdu.data, counter, counter_len);
	apdu.ins = TOKEN_INS_FIDO_SET_REPLAY_COUNTER;
	apdu.cla = 0x00; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = counter_len; apdu.le = 0; apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
                 printf("%s : %d\n",__FILE__,__LINE__);
		/* The smartcard responded an error */
		goto err;
	}
	if(resp.le != 0){
          printf("%s : %d\n",__FILE__,__LINE__);
		goto err;
	}

	return 0;
err:
	return -1;
}


#endif


