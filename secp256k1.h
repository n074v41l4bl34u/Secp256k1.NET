#ifndef _SECP256K1_
#define _SECP256K1_

#ifdef __cplusplus
extern "C" {
#endif

	void secp256k1_start(void);


	void secp256k1_stop(void);

	int secp256k1_ecdsa_verify(const unsigned char *msg, int msglen,
		const unsigned char *sig, int siglen,
		const unsigned char *pubkey, int pubkeylen);

	int secp256k1_ecdsa_sign(const unsigned char *msg, int msglen,
		unsigned char *sig, int *siglen,
		const unsigned char *seckey,
		const unsigned char *nonce);

	int secp256k1_ecdsa_sign_compact(const unsigned char *msg, int msglen,
		unsigned char *sig64,
		const unsigned char *seckey,
		const unsigned char *nonce,
		int *recid);

	int secp256k1_ecdsa_recover_compact(const unsigned char *msg, int msglen,
		const unsigned char *sig64,
		unsigned char *pubkey, int *pubkeylen,
		int compressed, int recid);

	int secp256k1_ecdsa_seckey_verify(const unsigned char *seckey);

	int secp256k1_ecdsa_pubkey_verify(const unsigned char *pubkey, int pubkeylen);

	int secp256k1_ecdsa_pubkey_create(unsigned char *pubkey, int *pubkeylen, const unsigned char *seckey, int compressed);

	int secp256k1_ecdsa_pubkey_decompress(unsigned char *pubkey, int *pubkeylen);

	int secp256k1_ecdsa_privkey_export(const unsigned char *seckey,
		unsigned char *privkey, int *privkeylen,
		int compressed);

	int secp256k1_ecdsa_privkey_import(unsigned char *seckey,
		const unsigned char *privkey, int privkeylen);

	int secp256k1_ecdsa_privkey_tweak(unsigned char *seckey, const unsigned char *tweak);
	int secp256k1_ecdsa_pubkey_tweak(unsigned char *pubkey, int pubkeylen, const unsigned char *tweak);

#ifdef __cplusplus
}
#endif

#endif
