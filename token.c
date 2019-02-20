/* Inlude elements related to ISO7816 and the board */
#include "autoconf.h"
#include "api/libtoken.h"
#include "api/syscall.h"
#define SMARTCARD_DEBUG CONFIG_SMARTCARD_DEBUG
//#define MEASURE_TOKEN_PERF

#include "api/print.h"

/****** Token operations **************/
/* [RB] FIXME: the layer handling the encryption and the integrity should
 * be abstracted and not dependent with the physical layer. For now these
 * layers are mixed because of the way ISO7816-3 mixes layers, but there should
 * be a clean way to split this and keep all the crypto code and the secure channel
 * code independent of the transport layer (so that the exact same code handles
 * tokens on ISO7816, I2C, SPI and so on).
 */

/* We describe hereafter the 'physical' layer to
 * communicate with our token. the rationale is to
 * distinguish between a 'clear text' channel before the
 * ECDH, and a secure channel protected in confidentiality
 * with AES-CTR and in integrity with a HMAC SHA256.
 * We are deemed to use AES with 128-bit keys because of
 * the lack of support for AES-192 and AES-256 in the current
 * mainstream Javacard cards.
 */

/* Self-synchronization anti-replay window of 10 attempts of a maximum size of AES blocks in an APDU */
#define ANTI_REPLAY_SELF_SYNC_WINDOW    (10*16)

int token_send_receive(token_channel *channel, SC_APDU_cmd *apdu, SC_APDU_resp *resp);

int decrypt_platform_keys(token_channel *channel, const char *pet_pin, uint32_t pet_pin_len, const databag *keybag, uint32_t keybag_num, databag *decrypted_keybag, uint32_t decrypted_keybag_num, uint32_t pbkdf2_iterations)
{
    uint8_t pbkdf[SHA512_DIGEST_SIZE];
    uint32_t pbkdf_len;
    hmac_context hmac_ctx;
    uint8_t hmac[SHA256_DIGEST_SIZE];
    uint32_t hmac_len = sizeof(hmac);
    aes_context aes_context;
    uint8_t *platform_salt = NULL;
    uint32_t platform_salt_len = 0;
    uint8_t *platform_iv = NULL;
    uint32_t platform_iv_len = 0;
    uint8_t *platform_hmac_tag = NULL;
    uint32_t platform_hmac_tag_len = 0;
    unsigned int i;
    uint8_t token_key[SHA512_DIGEST_SIZE];
    SC_APDU_cmd apdu;
    SC_APDU_resp resp;

    /* Sanity checks */
    if((pet_pin == NULL) || (keybag == NULL) || (decrypted_keybag == NULL)) {
        printf("one of pet_pin, keyback, decrypted_keybag is null\n");
        goto err;
    }
    /* Sanity checks on lengths
     * A Keybag contains at least an IV, a salt and a HMAC tag
     */
    if(keybag_num < 3) {
        printf("keybag_num is %d\n", keybag_num);
        goto err;
    }
    if(decrypted_keybag_num < (keybag_num - 3)) {
        printf("decrypted_keybag_num is %d\n", decrypted_keybag_num);
        goto err;
    }

    platform_iv = keybag[0].data;
    platform_iv_len = keybag[0].size;
    platform_salt = keybag[1].data;
    platform_salt_len = keybag[1].size;
    platform_hmac_tag = keybag[2].data;
    platform_hmac_tag_len = keybag[2].size;
    /* First of all, we derive our decryption and HMAC keys
     * from the PET PIN using PBKDF2.
     */
#if SMARTCARD_DEBUG
    printf("sending hmac_pbkdf2\n");
#endif
    pbkdf_len = sizeof(pbkdf);
    if(hmac_pbkdf2(SHA512, (unsigned char*)pet_pin, pet_pin_len, platform_salt, platform_salt_len, pbkdf2_iterations, SHA512_DIGEST_SIZE, pbkdf, &pbkdf_len))
    {
        goto err;
    }

    /* Once we have derived our PBKDF2 key, we ask the token for the decryption key */
    /* Sanity check: the secure channel must not be already negotiated */
    if((channel == NULL) || (channel->secure_channel == 1)) {
        printf("channel == NULL\n");
        goto err;
    }
    apdu.cla = 0x00; apdu.ins = TOKEN_INS_DERIVE_LOCAL_PET_KEY; apdu.p1 = 0x00; apdu.p2 = 0x00;
    apdu.lc = SHA512_DIGEST_SIZE; apdu.le = SHA512_DIGEST_SIZE; apdu.send_le = 1;
    memcpy(apdu.data, pbkdf, pbkdf_len);
#if SMARTCARD_DEBUG
    printf("sending to token\n");
#endif
    if(token_send_receive(channel, &apdu, &resp)) {
        printf("token send received fail\n");
        goto err;
    }

    /******* Smartcard response ***********************************/
    if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))) {
        /* The smartcard responded an error */
        printf("token response fails\n");
        goto err;
    }
    if(resp.le != SHA512_DIGEST_SIZE) {
        /* Bad response lenght */
        printf("bad response length\n");
        goto err;
    }
    memcpy(token_key, resp.data, SHA512_DIGEST_SIZE);

    /* First, we check the HMAC value, the HMAC key is the 256 right most bits of
     * the PBKDF2 value.
     */
    if(hmac_init(&hmac_ctx, token_key+32, SHA256_DIGEST_SIZE, SHA256))
    {
        printf("hmac init error\n");
        goto err;
    }
#if SMARTCARD_DEBUG
    printf("hmac init OK\n");
#endif
    hmac_update(&hmac_ctx, platform_iv, platform_iv_len);
    hmac_update(&hmac_ctx, platform_salt, platform_salt_len);
    for(i = 0; i < (keybag_num - 3); i++){
        hmac_update(&hmac_ctx, keybag[i+3].data, keybag[i+3].size);
    }
    if(hmac_finalize(&hmac_ctx, hmac, &hmac_len))
    {
        goto err;
    }
#if SMARTCARD_DEBUG
    printf("hmac final OK\n");
#endif
    /* Check the HMAC tag and return an error if there is an issue */
    if((hmac_len != SHA256_DIGEST_SIZE) || (platform_hmac_tag_len != SHA256_DIGEST_SIZE)){
        goto err;
    }
    if(!are_equal(hmac, platform_hmac_tag, hmac_len)){
        goto err;
    }
#if SMARTCARD_DEBUG
    printf("hmac equal OK\n");
#endif
    /* HMAC is OK, we can decrypt our data */
#if defined(__arm__)
    /* Use the protected masked AES ofr the platform keys decryption */
    if(aes_init(&aes_context, token_key, AES128, platform_iv, CTR, AES_DECRYPT, PROTECTED_AES, NULL, NULL, -1, -1)){
#else
        /* [RB] NOTE: if not on our ARM target, we use regular portable implementation for simulations */
    if(aes_init(&aes_context, token_key, AES128, platform_iv, CTR, AES_DECRYPT, AES_SOFT_MBEDTLS, NULL, NULL, -1, -1)){
#endif
        goto err;
    }
#if SMARTCARD_DEBUG
    printf("aes init OK\n");
#endif
    /* Decrypt all our data encapsulated in the keybag */
    for(i = 0; i < (keybag_num - 3); i++){
        if(keybag[i+3].size < decrypted_keybag[i].size){
            printf("overflow: %d, %d", keybag[i+3].size, decrypted_keybag[i].size);
            goto err;
        }
        decrypted_keybag[i].size = keybag[i+3].size;
        if(aes_exec(&aes_context, keybag[i+3].data, decrypted_keybag[i].data, keybag[i+3].size, -1, -1)){
            goto err;
        }
    }
#if SMARTCARD_DEBUG
    printf("aes OK\n");
#endif
    /* Erase the token key */
    memset(token_key, 0, sizeof(token_key));

    /* Copy the PBKDF2 iterations, the platform salt and the platform salt length in the secure channel context since
     * we will need it later.
     */
    if(platform_salt_len > sizeof(channel->platform_salt)){
        goto err;
    }
    channel->pbkdf2_iterations = pbkdf2_iterations;
    channel->platform_salt_len = platform_salt_len;
    memcpy(channel->platform_salt, platform_salt, platform_salt_len);

    return 0;

err:
    /* Erase the token key */
    memset(token_key, 0, sizeof(token_key));
#if SMARTCARD_DEBUG
    printf("Error: decrypt_platform_keys\n");
#endif
    return -1;
}

/* Secure channel negotiation:
 * We use an ECDH with mutual authentication in order to derive our session key and IV.
 */
/* [RB] FIXME: clean the sensitive values when they are no more used ... */
static int token_negotiate_secure_channel(token_channel *channel, const unsigned char *decrypted_platform_priv_key_data, uint32_t decrypted_platform_priv_key_data_len, const unsigned char *decrypted_platform_pub_key_data, uint32_t decrypted_platform_pub_key_data_len, const unsigned char *decrypted_token_pub_key_data, uint32_t decrypted_token_pub_key_data_len, ec_curve_type curve_type, unsigned int *remaining_tries){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;
	/* Our ECDSA key pair */
	ec_key_pair our_key_pair;
	/* The token ECDSA public key */
	ec_pub_key token_pub_key;
        /* The projective point we will use */
        prj_pt Q;
       /* The equivalent affine point */
        aff_pt Q_aff;
        nn d;
#ifdef USE_SIG_BLINDING
	nn scalar_b;
#endif
	uint8_t siglen;
        struct ec_sign_context sig_ctx;
        struct ec_verify_context verif_ctx;
        /* libecc internal structure holding the curve parameters */
        const ec_str_params *the_curve_const_parameters;
        ec_params curve_params;
	/* SHA256 context used to derive our secrets */
	sha256_context sha256_ctx;
	/* Shared secret buffer */
	uint8_t shared_secret[NN_MAX_BIT_LEN / 8];
	uint8_t digest[SHA256_DIGEST_SIZE];

	/* Sanity checks */
	if((channel == NULL) || (decrypted_platform_priv_key_data == NULL) || (decrypted_platform_pub_key_data == NULL) || (decrypted_token_pub_key_data == NULL) || (remaining_tries == NULL)){
		goto err;
	}

#ifdef MEASURE_TOKEN_PERF
	uint64_t start, end;
        sys_get_systick(&start, PREC_MILLI);
#endif

	/******* Reader answer ***********************************/
        /* Importing specific curve parameters from its type.
         */
        the_curve_const_parameters = ec_get_curve_params_by_type(curve_type);

        /* Get out if getting the parameters went wrong */
        if (the_curve_const_parameters == NULL) {
                goto err;
        }
        /* Now map the curve parameters to our libecc internal representation */
        import_params(&curve_params, the_curve_const_parameters);

	if(ec_get_sig_len(&curve_params, ECDSA, SHA256, &siglen)){
		goto err;
	}

	/* If there is not enough room in the short APDU for Q and the signature, get out */
	if(((3 * BYTECEIL(curve_params.ec_fp.p_bitlen)) + siglen) > SHORT_APDU_LC_MAX){
		goto err;
	}

	/* Import our platform ECDSA private and public keys */
	if(ec_structured_priv_key_import_from_buf(&(our_key_pair.priv_key),  &curve_params, decrypted_platform_priv_key_data, decrypted_platform_priv_key_data_len, ECDSA)){
		goto err;
	}
	if(ec_structured_pub_key_import_from_buf(&(our_key_pair.pub_key),  &curve_params, decrypted_platform_pub_key_data, decrypted_platform_pub_key_data_len, ECDSA)){
		goto err;
	}

        /* Initialize our projective point with the curve parameters */
        prj_pt_init(&Q, &(curve_params.ec_curve));

        /* Generate our ECDH parameters: a private scalar d and a public value Q = dG where G is the
         * curve generator.
         * d = random mod (q) where q is the order of the generator G.
	 * Note: we have chosen to do this the 'explicit way', but we could have used the ECDSA key pair generation
	 * primitive to handle the random private scalar d and its public counter part dG.
         */
        nn_init(&d, 0);
        if (nn_get_random_mod(&d, &(curve_params.ec_gen_order))) {
                goto err;
        }
#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	printf("[Token] BEGIN = %lld milliseconds\n", (end - start));
        sys_get_systick(&start, PREC_MILLI);
#endif
        /* Q = dG */
#ifdef USE_SIG_BLINDING
	/* NB: we use a blind scalar multiplication here since we do not want our
	 * private d to leak ...
	 */
	nn_init(&scalar_b, 0);
        if (nn_get_random_mod(&scalar_b, &(curve_params.ec_gen_order))) {
                goto err;
        }
        prj_pt_mul_monty_blind(&Q, &d, &(curve_params.ec_gen), &scalar_b, &(curve_params.ec_gen_order));
	/* Clear blinding scalar */
	nn_uninit(&scalar_b);
#else
        prj_pt_mul_monty(&Q, &d, &(curve_params.ec_gen));
#endif

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	printf("[Token] Q = dG Time taken = %lld milliseconds\n", (end - start));
        sys_get_systick(&start, PREC_MILLI);
#endif

	/* Normalize Q to have the unique representation (by moving to affine representation and back to projective) */
	prj_pt_to_aff(&Q_aff, &Q);
	ec_shortw_aff_to_prj(&Q, &Q_aff);

        /* Export Q to serialize it in the APDU.
         * Our export size is exactly 3 coordinates in Fp, so this should be 3 times the size
         * of an element in Fp.
         */
        if(prj_pt_export_to_buf(&Q, apdu.data,
                             3 * BYTECEIL(curve_params.ec_fp.p_bitlen))){
		goto err;
	}
	apdu.lc = 3 * BYTECEIL(curve_params.ec_fp.p_bitlen);

	/* Now compute the ECDSA signature of Q */
        if(ec_sign_init(&sig_ctx, &our_key_pair, ECDSA, SHA256)){
		goto err;
	}
	if(ec_sign_update(&sig_ctx, (const uint8_t*)apdu.data, apdu.lc)){
		goto err;
	}
	/* Append the signature in the APDU */
	if(ec_sign_finalize(&sig_ctx, &(apdu.data[apdu.lc]), siglen)){
		goto err;
	}
	apdu.lc += siglen;

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	printf("[Token] ECDSA SIGN = %lld milliseconds\n", (end - start));
#endif

	if(channel->error_recovery_sleep){
		sys_sleep(channel->error_recovery_sleep, SLEEP_MODE_DEEP);
	}
	/* The instruction to perform an ECDH is TOKEN_INS_SECURE_CHANNEL_INIT: the reader sends its random scalar
	 * and receives the card random scalar.
	 */
	apdu.cla = 0x00; apdu.ins = TOKEN_INS_SECURE_CHANNEL_INIT; apdu.p1 = 0x00; apdu.p2 = 0x00;
	apdu.le = apdu.lc; apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
		goto err;
	}

	/******* Smartcard response ***********************************/
	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
		/* The smartcard responded an error */
		if((resp.sw1 == TOKEN_INS_SECURE_CHANNEL_INIT) && (resp.sw2 == 0x00) && (resp.le == 2)){
			/* Get the remaining tries */
			*remaining_tries = (resp.data[0] << 8) | resp.data[1];
		}
		goto err;
	}
	if(resp.le != ((3 * BYTECEIL(curve_params.ec_fp.p_bitlen)) + (uint32_t)siglen)){
		/* This is not the size we are waiting for ... */
		goto err;
	}
	/* Import the token public key */
	if(ec_structured_pub_key_import_from_buf(&token_pub_key, &curve_params, decrypted_token_pub_key_data, decrypted_token_pub_key_data_len, ECDSA)){
		goto err;
	}

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&start, PREC_MILLI);
#endif

	/* Verify the signature */
	if(ec_verify_init(&verif_ctx, &token_pub_key, &(resp.data[resp.le-siglen]), siglen, ECDSA, SHA256)){
		goto err;
	}
	if(ec_verify_update(&verif_ctx, resp.data, resp.le-siglen)){
		goto err;
	}
	if(ec_verify_finalize(&verif_ctx)){
		goto err;
	}

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	printf("[Token] ECDSA VERIFY = %lld milliseconds\n", (end - start));
#endif

	/* Signature is OK, now extract the point from the APDU */
	if(prj_pt_import_from_buf(&Q, resp.data, 3 * BYTECEIL(curve_params.ec_fp.p_bitlen), &(curve_params.ec_curve))){
		/* NB: prj_pt_import_from_buf checks if the point is indeed on the
		 * curve or not, and returns an error if this is not the case ...
		 */
		goto err;
	}

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&start, PREC_MILLI);
#endif

	/* Now compute dQ where d is our secret */
#ifdef USE_SIG_BLINDING
	/* NB: we use a blind scalar multiplication here since we do not want our
	 * private d to leak ...
	 */
	nn_init(&scalar_b, 0);
        if (nn_get_random_mod(&scalar_b, &(curve_params.ec_gen_order))) {
                goto err;
        }
        prj_pt_mul_monty_blind(&Q, &d, &Q, &scalar_b, &(curve_params.ec_gen_order));
	/* Clear blinding scalar */
	nn_uninit(&scalar_b);
#else
        prj_pt_mul_monty(&Q, &d, &Q);
#endif


#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	printf("[Token] dQ = %lld milliseconds\n", (end - start));
        sys_get_systick(&start, PREC_MILLI);
#endif

	/* Clear d */
	nn_uninit(&d);
	/* Move to affine representation to get the unique representation of the point
	 * (the other party should send us a normalized point, but nevermind do it anyways).
	 */
        prj_pt_to_aff(&Q_aff, &Q);
	/* The shared secret is Q_aff.x, which is 32 bytes:
	 * we derive our AES 256-bit secret key, our 256-bit HMAC key as well as our initial IV from this value.
	 */
	fp_export_to_buf(shared_secret, BYTECEIL(curve_params.ec_fp.p_bitlen), &(Q_aff.x));

	/* AES Key = SHA-256("AES_SESSION_KEY" | shared_secret) (first 128 bits) */
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, (uint8_t*)"AES_SESSION_KEY", sizeof("AES_SESSION_KEY")-1);
	sha256_update(&sha256_ctx, shared_secret, BYTECEIL(curve_params.ec_fp.p_bitlen));
	sha256_final(&sha256_ctx, digest);
	memcpy(channel->AES_key, digest, 16);
	/* HMAC Key = SHA-256("HMAC_SESSION_KEY" | shared_secret) (256 bits) */
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, (uint8_t*)"HMAC_SESSION_KEY", sizeof("HMAC_SESSION_KEY")-1);
	sha256_update(&sha256_ctx, shared_secret, BYTECEIL(curve_params.ec_fp.p_bitlen));
	sha256_final(&sha256_ctx, channel->HMAC_key);
	/* IV = SHA-256("SESSION_IV" | shared_secret) (first 128 bits) */
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, (uint8_t*)"SESSION_IV", sizeof("SESSION_IV")-1);
	sha256_update(&sha256_ctx, shared_secret, BYTECEIL(curve_params.ec_fp.p_bitlen));
	sha256_final(&sha256_ctx, digest);
	memcpy(channel->IV, digest, 16);
	memcpy(channel->first_IV, channel->IV, 16);

#ifdef MEASURE_TOKEN_PERF
        sys_get_systick(&end, PREC_MILLI);
	printf("[Token] Symmetric crypto = %lld milliseconds\n", (end - start));
#endif

	/* Our secure channel is initialized */
	channel->secure_channel = 1;

        /* Uninit local variables */
        prj_pt_uninit(&Q);
        aff_pt_uninit(&Q_aff);

	return 0;
err:
#if SMARTCARD_DEBUG
        printf("Error: token_negotiate_secure_channel\n");
#endif
	return -1;
}

/* APDU encryption and integrity */
static int token_apdu_cmd_encrypt(token_channel *channel, SC_APDU_cmd *apdu){
	hmac_context hmac_ctx;
	uint8_t hmac[SHA256_DIGEST_SIZE];
	uint8_t tmp;
	uint32_t hmac_len = sizeof(hmac);

	/* Sanitiy checks */
	if((channel == NULL) || (apdu == NULL)){
		goto err;
	}
	if(!channel->secure_channel){
		/* Why encrypt since we do not have a secure channel yet? */
		goto err;
	}
	if((apdu->le > SHORT_APDU_LE_MAX) || (apdu->lc > SHORT_APDU_LC_MAX)){
		/* Sanity check: we only deal with short APDUs */
		goto err;
	}
	if(apdu->lc > (SHORT_APDU_LC_MAX - sizeof(hmac))){
		/* Not enough room for our HMAC */
		goto err;
	}

	/* Compute the integrity on the full encrypted data + CLA/INS/P1/P2, lc and le on 1 byte since we deal only with short APDUs */
	if(hmac_init(&hmac_ctx, channel->HMAC_key, sizeof(channel->HMAC_key), SHA256)){
		goto err;
	}
	/* Pre-append the IV for anti-replay on the integrity with empty data */
	hmac_update(&hmac_ctx, channel->IV, sizeof(channel->IV));
	hmac_update(&hmac_ctx, &(apdu->cla), 1);
	hmac_update(&hmac_ctx, &(apdu->ins), 1);
	hmac_update(&hmac_ctx, &(apdu->p1),  1);
	hmac_update(&hmac_ctx, &(apdu->p2),  1);
	if(apdu->lc != 0){
		/* Encryption */
		aes_context aes_context;
		/* Encrypt the APDU data with AES-CTR */
#if defined(__arm__)
		/* [RB] NOTE: we use a software masked AES for robustness against side channel attacks */
		if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_ENCRYPT, PROTECTED_AES, NULL, NULL, -1, -1)){
#else
		/* [RB] NOTE: if not on our ARM target, we use regular portable implementation for simulations */
		if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_ENCRYPT, AES_SOFT_MBEDTLS, NULL, NULL, -1, -1)){
#endif
			goto err;
		}
		if(aes_exec(&aes_context, apdu->data, apdu->data, apdu->lc, -1, -1)){
			goto err;
		}
		/* Increment the IV by as many blocks as necessary */
                add_iv(channel->IV, apdu->lc / AES_BLOCK_SIZE);

		/* Update the HMAC */
		tmp = (uint8_t)apdu->lc & 0xff;
		hmac_update(&hmac_ctx, &tmp, 1);
		hmac_update(&hmac_ctx, apdu->data, apdu->lc);
	}
	/* Always increment our anti-replay counter manually at least once fot the next data batch to send/receive */
	inc_iv(channel->IV);

	/* When encrypting an APDU, we always expect a response with at least 32 bytes of HMAC.
	 * In order to avoid any issue, we ask for a Le = 0 meaning that we expect a maximum amount of
	 * 256 bytes.
	 */
	apdu->send_le = 1;
	apdu->le = 0;
	tmp = (uint8_t)apdu->le & 0xff;
	hmac_update(&hmac_ctx, &tmp, 1);

	/* Add the integrity HMAC tag to the APDU data and increment the Lc
	 * size accordingly.
	 */
	if(hmac_finalize(&hmac_ctx, hmac, &hmac_len)){
		goto err;
	}
	if(hmac_len != sizeof(hmac)){
		goto err;
	}
	memcpy(&(apdu->data[apdu->lc]), hmac, sizeof(hmac));
	apdu->lc += sizeof(hmac);

	return 0;
err:
#if SMARTCARD_DEBUG
        printf("Error: token_apdu_cmd_encrypt\n");
#endif
	return -1;
}

#if __GNUC__
# pragma GCC push_options
# pragma GCC optimize("O0")
#endif
#if __clang__
# pragma clang optimize off
#endif
secbool check_hmac_again(const uint8_t *hmac, const uint8_t *hmac_recv, uint32_t size){
	if((hmac == NULL) || (hmac_recv == NULL)){
		goto err;
	}
	if(!are_equal(hmac, hmac_recv, size)){
		goto err;
	}
	if(!are_equal(hmac_recv, hmac, size)){
		goto err;
	}

	return sectrue;
err:
	return secfalse;
}
#if __clang__
# pragma clang optimize on
#endif
#if __GNUC__
# pragma GCC pop_options
#endif

static int token_apdu_resp_decrypt(token_channel *channel, SC_APDU_resp *resp){
	hmac_context hmac_ctx;
	uint8_t hmac[SHA256_DIGEST_SIZE];
	uint8_t hmac_recv[SHA256_DIGEST_SIZE];
	uint8_t tmp;
	int self_sync_attempts = ANTI_REPLAY_SELF_SYNC_WINDOW;
	uint32_t hmac_len = sizeof(hmac);

	/* Sanity check */
	if((channel == NULL) || (resp == NULL)){
		goto err;
	}
	if(!channel->secure_channel){
		goto err;
	}
	/* Response data contains at least a HMAC */
	if(resp->le < sizeof(hmac_recv)){
		goto err;
	}
	/* If we have not received a short APDU, this is an error */
	if(resp->le > SHORT_APDU_LE_MAX){
		goto err;
	}
	/* Copy the received HMAC */
	memcpy(hmac_recv, &(resp->data[resp->le - sizeof(hmac_recv)]), sizeof(hmac_recv));
	resp->le -= sizeof(hmac_recv);
CHECK_INTEGRITY_AGAIN:
	/* Check the integrity */
	if(hmac_init(&hmac_ctx, channel->HMAC_key, sizeof(channel->HMAC_key), SHA256)){
		goto err;
	}

	/* Pre-append the IV for anti-replay on the integrity with empty data */
	hmac_update(&hmac_ctx, channel->IV, sizeof(channel->IV));
	/* Update the HMAC with SW1 and SW2 */
	hmac_update(&hmac_ctx, &(resp->sw1), 1);
	hmac_update(&hmac_ctx, &(resp->sw2), 1);
	/* If we have data, update the HMAC  */
	if(resp->le > 0){
		tmp = (uint8_t)resp->le & 0xff;
		hmac_update(&hmac_ctx, &tmp, 1);
		hmac_update(&hmac_ctx, resp->data, resp->le);
	}
	/* Finalize the HMAC */
	if(hmac_finalize(&hmac_ctx, hmac, &hmac_len)){
		goto err;
	}
	if(hmac_len != sizeof(hmac)){
		goto err;
	}

	/* Compare the computed HMAC and the received HMAC */
	if(!are_equal(hmac, hmac_recv, sizeof(hmac))){
		/* Integrity is not OK, try to self-synchronize a bit ... */
		if(self_sync_attempts == 0){
			/* We have exhausted our self-sync attempts: return an error */
			goto err;
		}
		self_sync_attempts--;
		inc_iv(channel->IV);
		goto CHECK_INTEGRITY_AGAIN;
	}

	
	/* Sanity check against faults */
	if(check_hmac_again(hmac, hmac_recv, sizeof(hmac)) != sectrue){
		goto err;
	}

	/* Decrypt our data in place if there are some */
	if(resp->le != 0){
		aes_context aes_context;
		/* Decrypt the APDU response data with AES-CTR */
#if defined(__arm__)
		/* [RB] NOTE: we use a software masked AES for robustness against side channel attacks */
		if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_DECRYPT, PROTECTED_AES, NULL, NULL, -1, -1)){
#else
		/* [RB] NOTE: if not on our ARM target, we use regular portable implementation for simulations */
		if(aes_init(&aes_context, channel->AES_key, AES128, channel->IV, CTR, AES_DECRYPT, AES_SOFT_MBEDTLS, NULL, NULL, -1, -1)){
#endif
			goto err;
		}
		if(aes_exec(&aes_context, resp->data, resp->data, resp->le, -1, -1)){
			goto err;
		}
		/* Increment the IV by as many blocks as necessary */
                add_iv(channel->IV, resp->le / AES_BLOCK_SIZE);
	}
	/* Always increment our anti-replay counter manually at least once fot the next data batch to send/receive */
	inc_iv(channel->IV);

	return 0;
err:
#if SMARTCARD_DEBUG
        printf("Error: token_apdu_cmd_encrypt\n");
#endif
	return -1;
}


/*
 * Try to send an APDU on the physical line multiple times
 * in case of possible errors before giving up ...
 */
static int SC_send_APDU_with_errors(token_channel *channel, SC_APDU_cmd *apdu, SC_APDU_resp *resp, SC_Card *card){
	unsigned int num_tries;
	int ret;
	num_tries = 0;
	if(channel == NULL){
		ret = -1;
		goto err;
	}

	while(1){
		ret = SC_send_APDU(apdu, resp, card);
		num_tries++;
		if(!ret){
			return 0;
		}
#if SMARTCARD_DEBUG
        	printf("...retrying!\n");
#endif
		if(channel->error_recovery_sleep){
			sys_sleep(channel->error_recovery_sleep, SLEEP_MODE_DEEP);
		}

		if(ret && (num_tries >= channel->error_recovery_max_send_retries)){
			goto err;
		}
		if(!SC_is_smartcard_inserted(card)){
			/* Smartcard has been lost ... */
			goto err;
		}
		/* Wait the requested timeout with the card to reset the current APDU */
		SC_wait_card_timeout(card);
	}

err:
	return ret;
}

/* The token 'send'/'receive' primitive. Depending on the secure channel state, we
 * send raw or encrypted APDU data.
 * Because we want our secure channel to be compatible in T=0 and T=1, and since T=0
 * mixes the ISO layers and needs CLA/INS/P1/P2/P3, we do not encrypt these. They
 * are however part of the integrity tag computation in order to avoid integrity issues.
 *
 */
int token_send_receive(token_channel *channel, SC_APDU_cmd *apdu, SC_APDU_resp *resp){
#ifdef MEASURE_TOKEN_PERF
    uint64_t start, end;
#endif
    /* Sanity check */
    if((channel == NULL) || (apdu == NULL) || (resp == NULL)){
        goto err;
    }

#if SMARTCARD_DEBUG
    SC_print_APDU(apdu);
#endif
#ifdef MEASURE_TOKEN_PERF
    sys_get_systick(&start, PREC_MILLI);
#endif
    /* Channel is not initialized */
    if(!channel->channel_initialized){
        goto err;
    }

    /* Channel is initialized: are we in secure channel mode? */
    if(channel->secure_channel){
        /* In secure channel mode, we encrypt everything and send it.
         * Encrypt the APDU "in place" in order to avoid memory loss */
        /* If we have not space in the APDU, get out ... */
        if(apdu->lc > (SHORT_APDU_LC_MAX - SHA256_DIGEST_SIZE)){
            /* We must have some place for the integrity tag */
            goto err;
        }
        /* Encrypt the APDU and append the integrity tag */
        if(token_apdu_cmd_encrypt(channel, apdu)){
            goto err;
        }
        /* Send the encrypted APDU and receive the encrypted response */
        if(SC_send_APDU_with_errors(channel, apdu, resp, &(channel->card))){
            goto err;
        }
        /* Decrypt the response in place and check its integrity */
        if(token_apdu_resp_decrypt(channel, resp)){
            goto err;
        }
    }
    else{
        /* In non secure channel mode, we do not encrypt: send the raw
         * APDU and receive the raw response.
         */
        if(SC_send_APDU_with_errors(channel, apdu, resp, &(channel->card))){
            goto err;
        }
    }

#ifdef MEASURE_TOKEN_PERF
    sys_get_systick(&end, PREC_MILLI);
#endif
#if SMARTCARD_DEBUG
    SC_print_RESP(resp);
#endif
#ifdef MEASURE_TOKEN_PERF
    printf("[Token] [++++++++++++++] APDU send/receive took %lld milliseconds [++++++++++++++]\n", (end - start));
#endif

    return 0;

err:
#if SMARTCARD_DEBUG
    printf("APDU send/receive error (secure channel or lower layers errors)\n");
#endif

    return -1;
}


/* Update AES and HMAC session keys given an input string */
void token_channel_session_keys_update(token_channel *channel, const char *in, unsigned int in_len, unsigned char use_iv){
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256_context sha256_ctx;
    unsigned int i;

    /* Sanity check */
    if((channel == NULL) || (in == NULL)){
        return;
    }

    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, (unsigned char*)in, in_len);
    if(use_iv == 1){
        sha256_update(&sha256_ctx, channel->IV, sizeof(channel->IV));
    }
    sha256_final(&sha256_ctx, digest);
    for(i = 0; i < sizeof(channel->AES_key); i++){
        channel->AES_key[i] ^= digest[i];
    }
    for(i = 0; i < sizeof(channel->HMAC_key); i++){
        channel->HMAC_key[i] ^= digest[i];
    }

    return;
}

/****** Smartcard low level APDUs ****/

/* Select an applet */
int token_select_applet(token_channel *channel, const unsigned char *aid, unsigned int aid_len){
    SC_APDU_cmd apdu;
    SC_APDU_resp resp;

    if((channel == NULL) || (aid == NULL)){
	goto err;
    }

    apdu.cla = 0x00; apdu.ins = TOKEN_INS_SELECT_APPLET; apdu.p1 = 0x04; apdu.p2 = 0x00; apdu.lc = aid_len;
    apdu.le = 0x00; apdu.send_le = 1;
    memcpy(apdu.data, aid, aid_len);

    if(token_send_receive(channel, &apdu, &resp)){
        goto err;
    }

    /* Check return status */
    if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
        goto err;
    }

    return 0;

err:
    return -1;
}


/* Send a pin */
int token_send_pin(token_channel *channel, const char *pin, unsigned int pin_len, unsigned char *pin_ok, unsigned int *remaining_tries, token_pin_types pin_type){
	unsigned int i;
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;
	char padded_pin[16];

	if((pin == NULL) || (pin_ok == NULL) || (remaining_tries == NULL)){
		goto err;
	}

	*remaining_tries = 0;
	*pin_ok = 0;

	/* Some sanity checks here */
	if(pin_len > (SHORT_APDU_LC_MAX - SHA256_DIGEST_SIZE)){
		goto err;
	}
	if(pin_len > 15){
		goto err;
	}

	for(i = 0; i < pin_len; i++){
		padded_pin[i] = pin[i];
	}
	for(i= pin_len; i < (sizeof(padded_pin)-1); i++){
		padded_pin[i] = 0;
	}
	padded_pin[15] = pin_len;

	for(i = 0; i < sizeof(padded_pin); i++){
		apdu.data[i] = padded_pin[i];
	}
	if(pin_type == TOKEN_PET_PIN){
		apdu.ins = TOKEN_INS_UNLOCK_PET_PIN;
	}
	else if(pin_type == TOKEN_USER_PIN){
		apdu.ins = TOKEN_INS_UNLOCK_USER_PIN;
	}
	else{
		goto err;
	}
	apdu.cla = 0x00; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 16; apdu.le = 0x00; apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
		goto err;
	}

	/* Check the response */
	if(resp.le != 1){
		goto err;
	}
	/* Get the remaining tries */
	*remaining_tries = resp.data[0];

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
		/* The smartcard responded an error */
		*pin_ok = 0;
	}
	else{
		/* The pin is OK */
		*pin_ok = 1;
		/* Update our AES and HMAC sessions keys with information derived from the
		 * PIN: a SHA-256 hash of the PIN concatenated with the IV.
		 */
		token_channel_session_keys_update(channel, padded_pin, sizeof(padded_pin), 1);
	}

	return 0;
err:
	return -1;
}

/* Change user and PET PIN */
int token_change_pin(token_channel *channel, const char *pin, unsigned int pin_len, token_pin_types pin_type){
	unsigned int i;
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;
	char padded_pin[16];
        uint8_t pbkdf[SHA512_DIGEST_SIZE];
        uint32_t pbkdf_len;

	if((pin == NULL) || (channel == NULL)){
		goto err;
	}
	if(!channel->channel_initialized){
		goto err;
	}

	/* Some sanity checks here */
	if(pin_len > (SHORT_APDU_LC_MAX - SHA256_DIGEST_SIZE)){
		goto err;
	}
	if(pin_len > 15){
		goto err;
	}

	for(i = 0; i < pin_len; i++){
		padded_pin[i] = pin[i];
	}
	for(i = pin_len; i < (sizeof(padded_pin)-1); i++){
		padded_pin[i] = 0;
	}
	padded_pin[15] = pin_len;

	for(i = 0; i < sizeof(padded_pin); i++){
		apdu.data[i] = padded_pin[i];
	}
	if(pin_type == TOKEN_PET_PIN){
	        pbkdf_len = sizeof(pbkdf);
        	if(hmac_pbkdf2(SHA512, (unsigned char*)pin, pin_len, channel->platform_salt, channel->platform_salt_len, channel->pbkdf2_iterations, SHA512_DIGEST_SIZE, pbkdf, &pbkdf_len)){
                	goto err;
	        }
		if(pbkdf_len != SHA512_DIGEST_SIZE){
			goto err;
		}
		apdu.ins = TOKEN_INS_SET_PET_PIN;
		apdu.lc = 16 + SHA512_DIGEST_SIZE;
		memcpy(apdu.data+sizeof(padded_pin), pbkdf, SHA512_DIGEST_SIZE);
	}
	else if(pin_type == TOKEN_USER_PIN){
		apdu.ins = TOKEN_INS_SET_USER_PIN;
		apdu.lc = 16;
	}
	else{
		goto err;
	}
	apdu.cla = 0x00; apdu.p1 = 0x00; apdu.p2 = 0x00;
	apdu.le = 0x00; apdu.send_le = 0;
	if(token_send_receive(channel, &apdu, &resp)){
		goto err;
	}

	/* Check the response */
	if(resp.le != 0){
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
		/* The smartcard responded an error */
		goto err;
	}

	/* Update our AES and HMAC sessions keys with information derived from the
	 * PIN: a SHA-256 hash of the PIN concatenated with the IV.
	 */
	token_channel_session_keys_update(channel, padded_pin, sizeof(padded_pin), 1);

	return 0;
err:
	return -1;
}

/* Lock the token (close the user PIN authenticated session) */
int token_user_pin_lock(token_channel *channel){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;

	if((channel == NULL) || (channel->channel_initialized == 0)){
		goto err;
	}

	apdu.cla = 0x00; apdu.ins = TOKEN_INS_USER_PIN_LOCK; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = 0x00; apdu.send_le = 0;
	if(token_send_receive(channel, &apdu, &resp)){
		goto err;
	}

	/* Check the response */
	if(resp.le != 0){
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
		/* The smartcard responded an error */
		goto err;
	}

	return 0;
err:
	return -1;
}

/* Fully lock the token (close the user and pet PIN authenticated session, close the secure channel) */
int token_full_lock(token_channel *channel){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;

	if((channel == NULL) || (channel->channel_initialized == 0)){
		goto err;
	}

	apdu.cla = 0x00; apdu.ins = TOKEN_INS_FULL_LOCK; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = 0x00; apdu.send_le = 0;
	if(token_send_receive(channel, &apdu, &resp)){
		goto err;
	}

	/* Check the response */
	if(resp.le != 0){
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
		/* The smartcard responded an error */
		goto err;
	}

	return 0;
err:
	return -1;
}


/* Get the PET Name */
int token_get_pet_name(token_channel *channel, char *pet_name, unsigned int *pet_name_length){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;

	if((channel == NULL) || (channel->channel_initialized == 0)){
		goto err;
	}
	if((pet_name == NULL) || (pet_name_length == NULL)){
		goto err;
	}

	apdu.cla = 0x00; apdu.ins = TOKEN_INS_GET_PET_NAME; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = 0; apdu.le = 0x00; apdu.send_le = 1;
	if(token_send_receive(channel, &apdu, &resp)){
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
		/* The smartcard responded an error */
		goto err;
	}

	/* Check the input length */
	if(*pet_name_length < resp.le){
		goto err;
	}

	*pet_name_length  = resp.le;
	memcpy(pet_name, resp.data, resp.le);

	return 0;
err:
	return -1;
}

/* Set the PET Name */
int token_set_pet_name(token_channel *channel, const char *pet_name, unsigned int pet_name_length){
	SC_APDU_cmd apdu;
	SC_APDU_resp resp;

	if((channel == NULL) || (channel->channel_initialized == 0)){
		goto err;
	}
	if(pet_name == NULL){
		goto err;
	}
	if(pet_name_length > (SHORT_APDU_LC_MAX - SHA256_DIGEST_SIZE)){
		goto err;
	}

	apdu.cla = 0x00; apdu.ins = TOKEN_INS_SET_PET_NAME; apdu.p1 = 0x00; apdu.p2 = 0x00; apdu.lc = pet_name_length; apdu.le = 0x00; apdu.send_le = 0;
	memcpy(apdu.data, pet_name, pet_name_length);
	if(token_send_receive(channel, &apdu, &resp)){
		goto err;
	}

	if((resp.sw1 != (TOKEN_RESP_OK >> 8)) || (resp.sw2 != (TOKEN_RESP_OK & 0xff))){
		/* The smartcard responded an error */
		goto err;
	}

	return 0;
err:
	return -1;
}

int token_secure_channel_init(token_channel *channel, const unsigned char *decrypted_platform_priv_key_data, uint32_t decrypted_platform_priv_key_data_len, const unsigned char *decrypted_platform_pub_key_data, uint32_t decrypted_platform_pub_key_data_len, const unsigned char *decrypted_token_pub_key_data, uint32_t decrypted_token_pub_key_data_len, ec_curve_type curve_type, unsigned int *remaining_tries){

	if(channel == NULL){
		goto err;
	}
	/* [RB] NOTE: the rest of the sanity checks on the pointers should be performed by the lower
	 * functions.
	 */
	if(token_negotiate_secure_channel(channel, decrypted_platform_priv_key_data, decrypted_platform_priv_key_data_len, decrypted_platform_pub_key_data, decrypted_platform_pub_key_data_len, decrypted_token_pub_key_data, decrypted_token_pub_key_data_len, curve_type, remaining_tries)){
		goto err;
	}
	channel->curve = curve_type;
	return 0;
err:
	return -1;
}

/**********************************************************************/

static volatile bool map_voluntary;

int token_early_init(token_map_mode_t token_map)
{
    switch (token_map) {
        case TOKEN_MAP_AUTO:
            map_voluntary = false;
            return SC_fsm_early_init(SC_MAP_AUTO);
        case TOKEN_MAP_VOLUNTARY:
            map_voluntary = true;
            return SC_fsm_early_init(SC_MAP_VOLUNTARY);
        default:
            printf("invalid map mode\n");
            break;
    }
    return 1;
}

int token_map(void)
{
    if (map_voluntary) {
        return SC_fsm_map();
    }
    return 0;
}

int token_unmap(void)
{
    if (map_voluntary) {
        return SC_fsm_unmap();
    }
    return 0;
}



/* Zeroize the whole channel (physical related stuff and secure channel suff) */
void token_zeroize_channel(token_channel *channel){

	if(channel == NULL){
		return;
	}

        channel->channel_initialized = 0;
	memset((void*)&(channel->card), 0, sizeof(channel->card));
	channel->error_recovery_sleep = 0;
	channel->error_recovery_max_send_retries = 0;

	token_zeroize_secure_channel(channel);

	return;
}

/* Only zeroize the secure channel assets */
void token_zeroize_secure_channel(token_channel *channel){

	if(channel == NULL){
		return;
	}

        channel->secure_channel = 0;
        memset(channel->IV, 0, sizeof(channel->IV));
        memset(channel->first_IV, 0, sizeof(channel->first_IV));
        memset(channel->AES_key, 0, sizeof(channel->AES_key));
        memset(channel->HMAC_key, 0, sizeof(channel->HMAC_key));
	channel->pbkdf2_iterations = 0;
	channel->platform_salt_len = 0;
        memset(channel->platform_salt, 0, sizeof(channel->platform_salt));
	channel->curve = UNKNOWN_CURVE;

	return;
}
void token_zeroize_databag(databag *databag, unsigned int databag_size){
	unsigned int i;

	if(databag == NULL){
		return;
	}

	for(i = 0; i < databag_size; i++){
		memset(databag[i].data, 0, databag[i].size);
	}
	return;
}


int token_init(token_channel *channel){
	SC_Card card;

	if(channel == NULL){
		goto err;
	}

	channel->channel_initialized = 0;
	channel->secure_channel = 0;
	/* By default, error retries (in case of noise on the line) are set to 20 */
	channel->error_recovery_max_send_retries = 20;

        /* Initialize the card communication. First, try to negotiate PSS,
         * and do it without negotiation if it fails.
	 * In our use case, we expect the T=1 protocol to be used, so we
	 * force its usage.
         */
        if(SC_fsm_init(&card, 1, 1, 0, 64)){
               if(SC_fsm_init(&card, 0, 0, 0, 0)){
                       goto err;
               }
        }

	channel->card = card;
	channel->channel_initialized = 1;

	return 0;
err:
	return -1;
}


/*****************************************************************************/
/* This function helps to interact with the token regarding its security related operations.
 */
int token_unlock_ops_exec(token_channel *channel, const unsigned char *applet_AID, unsigned int applet_AID_len, const databag *keybag, uint32_t keybag_num, uint32_t pbkdf2_iterations, ec_curve_type curve_type, token_unlock_operations *op, uint32_t num_ops, cb_token_callbacks *callbacks, unsigned char *sig_pub_key, unsigned int *sig_pub_key_len, databag *saved_decrypted_keybag, uint32_t saved_decrypted_keybag_num){
	unsigned int i;
        char pet_pin[16] = { 0 };
       	char user_pin[16] = { 0 };
        char pet_name[32] = { 0 };
       	unsigned int pet_pin_len = 0, user_pin_len = 0, pet_name_len = 0;
	uint8_t got_pet_pin = 0, got_user_pin = 0;

	/* Sanity checks */
	if(channel == NULL){
		goto err;
	}

	if(op == NULL){
		goto err;
	}

	for(i = 0; i < num_ops; i++){
		switch(op[i]){
			/****************************************************************/
			case TOKEN_UNLOCK_INIT_TOKEN:{
			        /* Zeroize token channel */
			        token_zeroize_channel(channel);

			        /* Initialize the low level layer (ISO7816-3 or ISO14443-4) */
			        if(token_init(channel)){
			                goto err;
        			}

        			printf("[Token] Initialization is OK!\n");
			        SC_print_Card(&(channel->card));

				break;
			}
			/****************************************************************/
			case TOKEN_UNLOCK_ESTABLISH_SECURE_CHANNEL:{
#ifdef MEASURE_TOKEN_PERF
		        	uint64_t start_secure_channel, end_secure_channel;
			        uint64_t start_decrypt_keys, end_decrypt_keys;
#endif
				/* Close the current secure channel */
				token_zeroize_secure_channel(channel);

				if((keybag == NULL) || (keybag_num < 6)){
					goto err;
				}

			        /* Platform keys decrypted buffers */
			        unsigned char decrypted_token_pub_key_data[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE] = { 0 };
			        unsigned char decrypted_platform_priv_key_data[EC_STRUCTURED_PRIV_KEY_MAX_EXPORT_SIZE] = { 0 };
			        unsigned char decrypted_platform_pub_key_data[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE] = { 0 };
				/* The firmware signature public key is optional and might no be present in the keybag */
			        unsigned char decrypted_sig_pub_key_data[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE] = { 0 };
			        databag decrypted_keybag[] = {
  		                  { .data = decrypted_token_pub_key_data, .size = sizeof(decrypted_token_pub_key_data) },
                		  { .data = decrypted_platform_priv_key_data, .size = sizeof(decrypted_platform_priv_key_data) },
		                  { .data = decrypted_platform_pub_key_data, .size = sizeof(decrypted_platform_pub_key_data) },
		                  { .data = decrypted_sig_pub_key_data, .size = sizeof(decrypted_sig_pub_key_data) },
			        };
				/* NOTE: the actual sizes of the keybags will be adjusted by the lower layer function anyways,
				 * but double check it here ...
				 */
				unsigned int j;
				for(j = 0; j < 3; j++){
					if(keybag[j+3].size > decrypted_keybag[j].size){
						goto err;
					}
					else{
						decrypted_keybag[j].size = keybag[j+3].size;
					}
				}
				if(keybag_num > 6){
					if(keybag[3+3].size > decrypted_keybag[3].size){
						goto err;
					}
					else{
						decrypted_keybag[3].size = keybag[3+3].size;
					}
				}

#ifdef MEASURE_TOKEN_PERF
			        sys_get_systick(&start_decrypt_keys, PREC_MILLI);
#endif
 			        /* Select the applet on the token */
			        if(token_select_applet(channel, applet_AID, applet_AID_len)){
			                goto err;
       				}

			        /* Decrypt the platform keys */
			        if(decrypt_platform_keys(channel, pet_pin, pet_pin_len, keybag, keybag_num, decrypted_keybag, sizeof(decrypted_keybag)/sizeof(databag), pbkdf2_iterations)){
				        printf("[Platform] Failed to decrypt platform keys!\n");
					goto err;
				}
				/* Are we asked to save the decrypted signature key? */
				if((keybag_num > 6) && (sig_pub_key != NULL) && (sig_pub_key_len != NULL) && (*sig_pub_key_len >= decrypted_keybag[3].size)){
					memcpy(sig_pub_key, decrypted_sig_pub_key_data, decrypted_keybag[3].size);
					*sig_pub_key_len = decrypted_keybag[3].size;
				}
				/* Are asked to save the decrypted keybag for future usage? */
				if(saved_decrypted_keybag != NULL){
					if(saved_decrypted_keybag_num > keybag_num){
						goto err;
					}
					for(j = 0; j < saved_decrypted_keybag_num; j++){
						if(saved_decrypted_keybag[j].size < decrypted_keybag[j].size){
							goto err;
						}
						memset(saved_decrypted_keybag[j].data, 0, saved_decrypted_keybag[j].size);
						memcpy(saved_decrypted_keybag[j].data, decrypted_keybag[j].data, decrypted_keybag[j].size);
						saved_decrypted_keybag[j].size =  decrypted_keybag[j].size;
					}
				}

#ifdef MEASURE_TOKEN_PERF
      				sys_get_systick(&end_decrypt_keys, PREC_MILLI);
			        printf("[Token] Keys decryption is OK! Time taken = %lld milliseconds\n", (end_decrypt_keys - start_decrypt_keys));
#endif

#ifdef MEASURE_TOKEN_PERF
			        sys_get_systick(&start_secure_channel, PREC_MILLI);
#endif

				unsigned int remaining_tries = 0;
			        /* Initialize the secure channel with the token */
			        if(token_secure_channel_init(channel, decrypted_platform_priv_key_data, sizeof(decrypted_platform_priv_key_data), decrypted_platform_pub_key_data, sizeof(decrypted_platform_pub_key_data), decrypted_token_pub_key_data, sizeof(decrypted_token_pub_key_data), curve_type, &remaining_tries)){
			                /* Erase the decrypted platform keys, we don't need them anymore! */
					token_zeroize_databag(decrypted_keybag, sizeof(decrypted_keybag)/sizeof(databag));
			                printf("[XX] [Token] Secure channel negotiation error ...\n");
			                goto err;
			        }
			        /* Erase the decrypted platform keys, we don't need them anymore! */
				token_zeroize_databag(decrypted_keybag, sizeof(decrypted_keybag)/sizeof(databag));
#ifdef MEASURE_TOKEN_PERF
			        sys_get_systick(&end_secure_channel, PREC_MILLI);
			        printf("[Token] Secure channel negotiation is OK! Time taken = %lld milliseconds\n", (end_secure_channel - start_secure_channel));
#else
			        printf("[Token] Secure channel negotiation is OK!\n");
#endif

				break;
			}
			/****************************************************************/
			case TOKEN_UNLOCK_ASK_PET_PIN:{
				/* Ask PET pin to the user */
				if((callbacks == NULL) || (callbacks->request_pin == NULL)){
					goto err;
				}
			        /* Ask the user for the PET PIN */
			        pet_pin_len = sizeof(pet_pin);
			        if(callbacks->request_pin(pet_pin, &pet_pin_len, TOKEN_PET_PIN, TOKEN_PIN_AUTHENTICATE)){
				        printf("[Pet Pin] Failed to ask for pet pin!\n");
					callbacks->acknowledge_pin(TOKEN_ACK_INVALID, TOKEN_PET_PIN, TOKEN_PIN_AUTHENTICATE, 0);
		                	goto err;
        			}
				got_pet_pin = 1;
				break;
			}
			/****************************************************************/
			case TOKEN_UNLOCK_PRESENT_PET_PIN:{
				uint8_t pin_ok;
				unsigned int remaining_tries = 0;
				if((callbacks == NULL) || (callbacks->request_pin == NULL) || (callbacks->acknowledge_pin == NULL)){
					goto err;
				}
				/* If we have already asked for the PET pin, no need to do it again! */
				if(!got_pet_pin){
				        /* Ask the user for the PET PIN */
			        	pet_pin_len = sizeof(pet_pin);
				        if(callbacks->request_pin(pet_pin, &pet_pin_len, TOKEN_PET_PIN, TOKEN_PIN_AUTHENTICATE)){
					        printf("[Pet Pin] Failed to ask for pet pin!\n");
						callbacks->acknowledge_pin(TOKEN_ACK_INVALID, TOKEN_PET_PIN, TOKEN_PIN_AUTHENTICATE, remaining_tries);
		        	        	goto err;
        				}
				}
				/* Send the PIN to token */
				if(token_send_pin(channel, pet_pin, pet_pin_len, &pin_ok, &remaining_tries, TOKEN_PET_PIN)){
					printf("[Token] Error sending PET pin\n");
					callbacks->acknowledge_pin(TOKEN_ACK_INVALID, TOKEN_PET_PIN, TOKEN_PIN_AUTHENTICATE, remaining_tries);
					goto err;
				}
				if(!pin_ok){
					printf("[Token] PET PIN is NOT OK, remaining tries = %d\n", remaining_tries);
					if (callbacks->acknowledge_pin(TOKEN_ACK_INVALID, TOKEN_PET_PIN, TOKEN_PIN_AUTHENTICATE, remaining_tries)) {
						goto err;
					}
				}
				else{
					if(callbacks->acknowledge_pin(TOKEN_ACK_VALID, TOKEN_PET_PIN, TOKEN_PIN_AUTHENTICATE, remaining_tries)){
						goto err;
					}
				}
				break;
			}
			/****************************************************************/
			case TOKEN_UNLOCK_ASK_USER_PIN:{
				/* Ask user pin to the user */
				if((callbacks == NULL) || (callbacks->request_pin == NULL) || (callbacks->acknowledge_pin == NULL)){
					goto err;
				}
			        /* Ask the user for the PET PIN */
			        user_pin_len = sizeof(user_pin);
			        if(callbacks->request_pin(user_pin, &user_pin_len, TOKEN_USER_PIN, TOKEN_PIN_AUTHENTICATE)){
				        printf("[User Pin] Failed to ask for pet pin!\n");
					callbacks->acknowledge_pin(TOKEN_ACK_INVALID, TOKEN_USER_PIN, TOKEN_PIN_AUTHENTICATE, 0);
		                	goto err;
        			}
				got_user_pin = 1;
				break;
			}
			/****************************************************************/
			case TOKEN_UNLOCK_PRESENT_USER_PIN:{
				uint8_t pin_ok;
				unsigned int remaining_tries = 0;
				if((callbacks == NULL) || (callbacks->request_pin == NULL) || (callbacks->acknowledge_pin == NULL)){
					goto err;
				}
				/* If we have already asked for the user pin, no need to do it again! */
				if(!got_user_pin){
					if(callbacks->request_pin == NULL){
						goto err;
					}
				        /* Ask the user for the user PIN */
			        	user_pin_len = sizeof(user_pin);
				        if(callbacks->request_pin(user_pin, &user_pin_len, TOKEN_USER_PIN, TOKEN_PIN_AUTHENTICATE)){
					        printf("[User Pin] Failed to ask for user pin!\n");
						callbacks->acknowledge_pin(TOKEN_ACK_INVALID, TOKEN_USER_PIN, TOKEN_PIN_AUTHENTICATE, 0);
		        	        	goto err;
        				}
				}
				/* Send the PIN to token */
				if(token_send_pin(channel, user_pin, user_pin_len, &pin_ok, &remaining_tries, TOKEN_USER_PIN)){
					printf("[Token] Error sending user pin\n");
					callbacks->acknowledge_pin(TOKEN_ACK_INVALID, TOKEN_USER_PIN, TOKEN_PIN_AUTHENTICATE, remaining_tries);
					goto err;
				}
				if(!pin_ok){
					printf("[Token] user PIN is NOT OK, remaining tries = %d\n", remaining_tries);
					if(callbacks->acknowledge_pin(TOKEN_ACK_INVALID, TOKEN_USER_PIN, TOKEN_PIN_AUTHENTICATE, remaining_tries)){
						goto err;
					}
				}
				else{
					if(callbacks->acknowledge_pin(TOKEN_ACK_VALID, TOKEN_USER_PIN, TOKEN_PIN_AUTHENTICATE, remaining_tries)){
						goto err;
					}
				}
				break;
			}
			/****************************************************************/
			case TOKEN_UNLOCK_CONFIRM_PET_NAME:{
				if((callbacks == NULL) || (callbacks->request_pet_name_confirmation == NULL)){
					goto err;
				}
			        /*************** Get PET Name */
			        pet_name_len = sizeof(pet_name);
			        if(token_get_pet_name(channel, pet_name, &pet_name_len)){
			                printf("[Token] ERROR when getting the PET name\n");
			                goto err;
			        }
				if(callbacks->request_pet_name_confirmation(pet_name, pet_name_len)){
					printf("[Token] Failed to confirm the PET name by the user\n");
					goto err;
				}
				break;
			}
			/****************************************************************/
			case TOKEN_UNLOCK_CHANGE_PET_PIN:{
				if((callbacks == NULL) || (callbacks->request_pin == NULL) || (callbacks->acknowledge_pin == NULL)){
					goto err;
				}
				/* Ask the user the new PET pin */
			        pet_pin_len = sizeof(pet_pin);
			        if(callbacks->request_pin(pet_pin, &pet_pin_len, TOKEN_PET_PIN, TOKEN_PIN_MODIFY)){
				        printf("[Pet Pin] Failed to ask for the NEW pet pin!\n");
					callbacks->acknowledge_pin(TOKEN_ACK_INVALID, TOKEN_PET_PIN, TOKEN_PIN_MODIFY, 0);
		                	goto err;
        			}
				/* Modify the pet pin */
				if(token_change_pin(channel, pet_pin, pet_pin_len, TOKEN_PET_PIN)){
					goto err;
				}
				callbacks->acknowledge_pin(TOKEN_ACK_VALID, TOKEN_PET_PIN, TOKEN_PIN_MODIFY, 0);
				break;
			}
			/****************************************************************/
			case TOKEN_UNLOCK_CHANGE_USER_PIN:{
				if((callbacks == NULL) || (callbacks->request_pin == NULL) || (callbacks->acknowledge_pin == NULL)){
					goto err;
				}
				/* Ask the user the new user pin */
			        user_pin_len = sizeof(user_pin);
			        if(callbacks->request_pin(user_pin, &user_pin_len, TOKEN_USER_PIN, TOKEN_PIN_MODIFY)){
				        printf("[User Pin] Failed to ask for the NEW user pin!\n");
					callbacks->acknowledge_pin(TOKEN_ACK_INVALID, TOKEN_USER_PIN, TOKEN_PIN_MODIFY, 0);
		                	goto err;
        			}
				/* Modify the pet pin */
				if(token_change_pin(channel, user_pin, user_pin_len, TOKEN_USER_PIN)){
					goto err;
				}
				callbacks->acknowledge_pin(TOKEN_ACK_VALID, TOKEN_USER_PIN, TOKEN_PIN_MODIFY, 0);
				break;
			}
			/****************************************************************/
			case TOKEN_UNLOCK_CHANGE_PET_NAME:{
				if((callbacks == NULL) || (callbacks->request_pet_name == NULL)){
					goto err;
				}
				/* Ask the user for the new pet name */
			        pet_name_len = sizeof(pet_name);
			        if(callbacks->request_pet_name(pet_name, &pet_name_len)){
				        printf("[Pet Name] Failed to ask for the NEW pet name!\n");
					if(callbacks->request_pet_name_confirmation(pet_name, pet_name_len)){
						printf("[Token] Failed to confirm the PET name by the user\n");
						goto err;
					}
		                	goto err;
        			}
				/* Modify the pet name */
				if(token_set_pet_name(channel, pet_name, pet_name_len)){
					goto err;
				}
				break;
			}
			/****************************************************************/
			default:
				goto err;
		}
	}

	/* Erase our sensitive stuff */
	memset(pet_pin, 0, pet_pin_len);
	memset(user_pin, 0, user_pin_len);
	memset(pet_name, 0, pet_name_len);

	return 0;
err:
	/* Erase our sensitive stuff */
	memset(pet_pin, 0, pet_pin_len);
	memset(user_pin, 0, user_pin_len);
	memset(pet_name, 0, pet_name_len);

	return -1;
}



