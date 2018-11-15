#ifndef __SMARTCARD_TOKEN_H__
#define __SMARTCARD_TOKEN_H__

#include "libsmartcard.h"

/* Include libecc headers for the crypto part 
 * (asymmetric ECC and hash functions).
 */
#include "libsig.h"

/* Include the HMAC header */
#include "hmac.h"

/* Include the AES header */
#include "aes.h"


/* The token communication channel and the cryptographic material to handle
 * the secure channel.
 */
typedef struct {
        uint8_t channel_initialized;
        SC_Card card; /* The card information needed for the low level operations */
        uint8_t secure_channel; /* Boolean telling if the channel is secure or not yet */
        uint8_t IV[16]; /* Initialization Vector. We use this as an anti-replay mechanism. */
        uint8_t first_IV[16]; /* First Initialization Vector value. We use this as a random seed for some key derivations. */
        /* Symmetric session key for confidentiality 128-bit AES key. */
        uint8_t AES_key[16];
        /* HMAC SHA-256 secret key */
        uint8_t HMAC_key[32];
	/*********************/
	/* PBKDF2 iterations */
	uint32_t pbkdf2_iterations;
	/* Platform salt */
	uint8_t platform_salt[32];
	/* Platform salt length */
	uint32_t platform_salt_len;
} token_channel;

typedef enum {
        TOKEN_PET_PIN = 1,
        TOKEN_USER_PIN = 2,
} token_pin_types;


/*
 * token validation enumerate with
 * anti hardened encoding
 */
typedef enum {
  TOKEN_ACK_VALID   = 0x100101101,
  TOKEN_ACK_INVALID = 0x101000111,
} token_ack_state;

/* A databag structure is a pointer to data
 * and an information about its size.
 */
typedef struct {
        uint8_t *data;
        uint32_t size;
} databag;

/* Our common token instructions */
enum token_instructions {
        TOKEN_INS_SELECT_APPLET = 0xA4,
        TOKEN_INS_SECURE_CHANNEL_INIT = 0x00,
        TOKEN_INS_UNLOCK_PET_PIN = 0x01,
        TOKEN_INS_UNLOCK_USER_PIN = 0x02,
        TOKEN_INS_SET_USER_PIN = 0x03,
        TOKEN_INS_SET_PET_PIN = 0x04,
        TOKEN_INS_SET_PET_NAME = 0x05,
        TOKEN_INS_USER_PIN_LOCK = 0x06,
        TOKEN_INS_FULL_LOCK = 0x07,
        TOKEN_INS_GET_PET_NAME = 0x08,
        TOKEN_INS_GET_RANDOM = 0x09,
	TOKEN_INS_DERIVE_LOCAL_PET_KEY = 0x0a,
        /* FIXME: To be removed, for debug purpose only */
        TOKEN_INS_ECHO_TEST = 0x0b,
        TOKEN_INS_SECURE_CHANNEL_ECHO = 0x0c,
};

enum token_responses {
        TOKEN_RESP_OK = 0x9000,
};


/* Callbacks */
typedef enum {
	TOKEN_PIN_AUTHENTICATE = 0,
	TOKEN_PIN_MODIFY = 1,
} token_pin_actions;

typedef int (*cb_token_request_pin_t)(char *pin, unsigned int *pin_len, token_pin_types pin_type, token_pin_actions action);
typedef int (*cb_token_acknowledge_pin_t)(token_ack_state ack, token_pin_types pin_type, token_pin_actions action, uint32_t remaining_tries);
typedef int (*cb_token_request_pet_name_t)(char *pet_name, unsigned int *pet_name_len);
typedef int (*cb_token_request_pet_name_confirmation_t)(const char *pet_name, unsigned int pet_name_len);

typedef struct {
	cb_token_request_pin_t                   request_pin;
	cb_token_acknowledge_pin_t               acknowledge_pin;
	cb_token_request_pet_name_t              request_pet_name;
	cb_token_request_pet_name_confirmation_t request_pet_name_confirmation;
} cb_token_callbacks;

typedef enum {
	TOKEN_UNLOCK_INIT_TOKEN               = 0,
	TOKEN_UNLOCK_ESTABLISH_SECURE_CHANNEL = 1,
	TOKEN_UNLOCK_ASK_PET_PIN              = 2,
	TOKEN_UNLOCK_PRESENT_PET_PIN          = 3,
	TOKEN_UNLOCK_ASK_USER_PIN             = 4,
	TOKEN_UNLOCK_PRESENT_USER_PIN         = 5,
	TOKEN_UNLOCK_CONFIRM_PET_NAME         = 6,
	TOKEN_UNLOCK_CHANGE_PET_PIN           = 7,
	TOKEN_UNLOCK_CHANGE_USER_PIN          = 8,
	TOKEN_UNLOCK_CHANGE_PET_NAME          = 9,
} token_unlock_operations;


/* We define here the type of AES we use to protect the channel to
 * communicate with the token.
 */
#define PROTECTED_AES AES_SOFT_ANSSI_MASKED

/******* Crypto helpers ****************/

static inline void inc_iv(uint8_t IV[16]){
    int i;
    for(i = 16; i > 0; i--){
        if(++IV[i-1]){
            break;
        }
    }

    return;
}

static inline void add_iv(uint8_t IV[16], unsigned int inc){
    unsigned int i;

    for(i = 0; i < inc; i++){
        inc_iv(IV);
    }

    return;
}

int token_early_init(void);

/* High level functions to communicate with the token */
int token_init(token_channel *channel);

void token_zeroize_channel(token_channel *channel);

void token_zeroize_secure_channel(token_channel *channel);

void token_zeroize_databag(databag *databag, unsigned int databag_size);

int token_early_init();

int token_select_applet(token_channel *channel, const unsigned char *aid, unsigned int aid_len);

int decrypt_platform_keys(token_channel *channel, const char *pet_pin, uint32_t pet_pint_len, const databag *keybag, uint32_t keybag_num, databag *decrypted_keybag, uint32_t decrypted_keybag_num, uint32_t pbkdf2_iterations);

int token_secure_channel_init(token_channel *channel, const unsigned char *decrypted_platform_priv_key_data, uint32_t decrypted_platform_priv_key_data_len, const unsigned char *decrypted_platform_pub_key_data, uint32_t decrypted_platform_pub_key_data_len, const unsigned char *decrypted_token_pub_key_data, uint32_t decrypted_token_pub_key_data_len, ec_curve_type curve_type, unsigned int *remaining_tries);

int token_send_receive(token_channel *channel, SC_APDU_cmd *apdu, SC_APDU_resp *resp);

int token_send_pin(token_channel *channel, const char *pin, unsigned int pin_len, unsigned char *pin_ok, unsigned int *remaining_tries, token_pin_types pin_type);

int token_get_pet_name(token_channel *channel, char *pet_name, unsigned int *pet_name_length);

int token_set_pet_name(token_channel *channel, const char *pet_name, unsigned int pet_name_length);

int token_change_pin(token_channel *channel, const char *pin, unsigned int pin_len, token_pin_types pin_type);

int token_user_pin_lock(token_channel *channel);

int token_full_lock(token_channel *channel);

int token_unlock_ops_exec(token_channel *channel, const unsigned char *applet_AID, unsigned int applet_AID_len, const databag *keybag, uint32_t keybag_num, uint32_t pbkdf2_iterations, ec_curve_type curve_type, token_unlock_operations *op, uint32_t num_ops, cb_token_callbacks *callbacks, unsigned char *decrypted_sig_pub_key_data, unsigned int *decrypted_sig_pub_key_data_len);

#endif /* __SMARTCARD_TOKEN_H__ */
