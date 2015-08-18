#include "include/secp256k1.h"

using namespace System;
using namespace System::Threading;
using namespace System::Security::Cryptography;
using namespace System::Runtime::InteropServices;

namespace Secp256k1
{
	/// <summary>Encapsulates secp256k1 signature related operations</summary>
	public ref class Signatures
	{
		static Signatures()
		{
			Context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
		}
		static String ^PrivateKeyLengthError = "Private key must be 32 bytes long.";
		static String ^CompactSignatureLengthError = "Compact signatures must be 64 bytes long.";
		static String ^MessageLengthError = "Message must be 32 bytes long (SHA-256 it!)";
		static secp256k1_context_t *Context;

		static array<Byte> ^SerializePublicKey(secp256k1_pubkey_t *publicKey, bool compressed)
		{
			array<Byte> ^pubkey = gcnew array<Byte>(compressed ? 33 : 65);
			int pubkeylen = pubkey->Length;
			{
				pin_ptr<Byte> pubkeybytes = &pubkey[0];
				if (!secp256k1_ec_pubkey_serialize(Context, pubkeybytes, &pubkeylen, publicKey, compressed ? 1 : 0))
					return nullptr;
			}
			if (pubkeylen == pubkey->Length)
				return pubkey;
			array<Byte> ^smallkey = gcnew array<Byte>(pubkeylen);
			array<Byte>::Copy(pubkey, 0, smallkey, 0, pubkeylen);
			return smallkey;
		}

	public:
		/// <summary>Verifies that a signature is valid.</summary>
		/// <param name="message">The message to verify.  This data is not hashed.  For use with bitcoins, you probably want to double-SHA256 hash this before calling this method.</param>
		/// <param name="signature">The signature to test for validity. This must not be a compact key (Use RecoverKeyFromCompact instead).</param>
		/// <param name="publicKey">The public key used to create the signature.</param>
		static bool Verify(array<Byte> ^message, array<Byte> ^signature, array<Byte> ^publicKey)
		{
			if (message == nullptr || signature == nullptr || publicKey == nullptr)
				throw gcnew ArgumentNullException();
			if (message->Length != 32)
				throw gcnew ArgumentOutOfRangeException(MessageLengthError);

			secp256k1_ecdsa_signature_t sig;
			secp256k1_pubkey_t key;

			{
				pin_ptr<Byte> keyptr = &publicKey[0];
				if (!secp256k1_ec_pubkey_parse(Context, &key, keyptr, publicKey->Length))
					return false;
			}
			{
				pin_ptr<Byte> signatureptr = &signature[0];
				if (!secp256k1_ecdsa_signature_parse_der(Context, &sig, signatureptr, signature->Length))
					return false;
			}

			pin_ptr<Byte> messageptr = &message[0];
			if (!secp256k1_ecdsa_verify(Context, messageptr, &sig, &key))
				return false;

			return true;
		}
		/// <summary>Signs a message and returns the signature.  Returns null on failure.</summary>
		/// <param name="message">The message to sign.  This data is not hashed.  For use with bitcoins, you probably want to double-SHA256 hash this before calling this method.</param>
		/// <param name="privateKey">The private key to use to sign the message.</param>
		static array<Byte> ^Sign(array<Byte> ^message, array<Byte> ^privateKey)
		{
			if (message == nullptr || privateKey == nullptr)
				throw gcnew ArgumentNullException();
			if (privateKey->Length != 32)
				throw gcnew ArgumentOutOfRangeException(PrivateKeyLengthError);
			if (message->Length != 32)
				throw gcnew ArgumentOutOfRangeException(MessageLengthError);

			secp256k1_ecdsa_signature_t sig;
			{
				pin_ptr<Byte> messageptr = &message[0];
				pin_ptr<Byte> keyptr = &privateKey[0];
				if (!secp256k1_ecdsa_sign(Context, messageptr, &sig, keyptr, 0, 0))
					return nullptr;
			}
			array<Byte> ^sigbytes = gcnew array<Byte>(70);
			int sigptrlen = sigbytes->Length;
			{
				pin_ptr<Byte> sigptr = &sigbytes[0];
				if (!secp256k1_ecdsa_signature_serialize_der(Context, sigptr, &sigptrlen, &sig))
					if (sigptrlen > sigbytes->Length)
					{
						sigbytes = gcnew array<Byte>(sigptrlen);
						sigptr = &sigbytes[0];
						if (!secp256k1_ecdsa_signature_serialize_der(Context, sigptr, &sigptrlen, &sig))
							return nullptr;
					}
					else
						return nullptr;
			}
			if (sigptrlen == sigbytes->Length)
				return sigbytes;
			array<Byte> ^smallsignature = gcnew array<Byte>(sigptrlen);
			array<Byte>::Copy(sigbytes, 0, smallsignature, 0, sigptrlen);
			return smallsignature;

		}
		/// <summary>Signs a message and returns the signature in compact form.  Returns null on failure.</summary>
		/// <param name="message">The message to sign.  This data is not hashed.  For use with bitcoins, you probably want to double-SHA256 hash this before calling this method.</param>
		/// <param name="privateKey">The private key to use to sign the message.</param>
		/// <param name="recoveryId">This will contain the recovery ID needed to retrieve the key from the compact signature using the RecoverKeyFromCompact method.</param>
		static array<Byte> ^SignCompact(array<Byte> ^message, array<Byte> ^privateKey, [Out] int %recoveryId)
		{
			if (message == nullptr || privateKey == nullptr)
				throw gcnew ArgumentNullException();
			if (privateKey->Length != 32)
				throw gcnew ArgumentOutOfRangeException(PrivateKeyLengthError);
			if (message->Length != 32)
				throw gcnew ArgumentOutOfRangeException(MessageLengthError);

			recoveryId = 0;

			secp256k1_ecdsa_signature_t sig;
			{
				pin_ptr<Byte> messageptr = &message[0];
				pin_ptr<Byte> keyptr = &privateKey[0];
				if (!secp256k1_ecdsa_sign(Context, messageptr, &sig, keyptr, 0, 0))
					return nullptr;
			}
			array<Byte> ^sigbytes = gcnew array<Byte>(64);
			int recid;
			{
				pin_ptr<Byte> sigptr = &sigbytes[0];
				if (!secp256k1_ecdsa_signature_serialize_compact(Context, sigptr, &recid, &sig))
					return nullptr;
			}
			recoveryId = recid;
			return sigbytes;
		}
		/// <summary>Recovers a public key from a compact signature.  Success also indicates a valid signature.  Returns null on failure.</summary>
		/// <param name="message">The message that was signed.  This data is not hashed.  For use with bitcoins, you probably want to double-SHA256 hash this before calling this method.</param>
		/// <param name="signature">The signature provided that will also be tested for validity.  A return value other than null indicates this signature is valid.</param>
		/// <param name="recoveryId">The recovery ID provided during a call to the SignCompact method.</param>
		/// <param name="compressed">True if the public key is to be compressed.</param>
		static array<Byte> ^RecoverKeyFromCompact(array<Byte> ^message, array<Byte> ^signature, int recoveryId, bool compressed)
		{
			if (message == nullptr || signature == nullptr)
				throw gcnew ArgumentNullException();
			if (signature->Length != 64)
				throw gcnew ArgumentOutOfRangeException(CompactSignatureLengthError);
			if (message->Length != 32)
				throw gcnew ArgumentOutOfRangeException(MessageLengthError);

			secp256k1_ecdsa_signature_t sig;
			{
				pin_ptr<Byte> sigptr = &signature[0];
				if (!secp256k1_ecdsa_signature_parse_compact(Context, &sig, sigptr, recoveryId))
					return nullptr;
			}
			secp256k1_pubkey_t key;
			{
				pin_ptr<Byte> messageptr = &message[0];
				if (!secp256k1_ecdsa_recover(Context, messageptr, &sig, &key))
					return nullptr;
			}
			return SerializePublicKey(&key, compressed);
		}
		/// <summary>Verifies that a private key is valid.  Returns true if valid.</summary>
		/// <param name="privateKey">A private key to test for validity.</param>
		static bool VerifyPrivateKey(array<Byte> ^privateKey)
		{
			if (privateKey == nullptr || privateKey->Length != 32)
				return false;
			pin_ptr<Byte> keyptr = &privateKey[0];
			return secp256k1_ec_seckey_verify(Context, keyptr) == 1;
		}
		/// <summary>Gets the public key associated with a private key.  Returns null on failure.</summary>
		/// <param name="privateKey">The private key from which to extract the public key.</param>
		/// <param name="compressed">True if the public key is to be compressed.</param>
		static array<Byte> ^GetPublicKey(array<Byte> ^privateKey, bool compressed)
		{
			if (privateKey == nullptr)
				throw gcnew ArgumentNullException();
			if (privateKey->Length != 32)
				throw gcnew ArgumentOutOfRangeException(PrivateKeyLengthError);

			secp256k1_pubkey_t key;
			{
				pin_ptr<Byte> privkeyptr = &privateKey[0];
				if (!secp256k1_ec_pubkey_create(Context, &key, privkeyptr))
					return nullptr;
			}
			return SerializePublicKey(&key, compressed);
		}
	};
};