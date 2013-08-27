#include "secp256k1.h"

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
			secp256k1_start();
		}
		static ThreadLocal<RNGCryptoServiceProvider ^> ^Randoms = gcnew ThreadLocal<RNGCryptoServiceProvider ^>(gcnew Func<RNGCryptoServiceProvider ^>(CreateRNG));
		static RNGCryptoServiceProvider ^CreateRNG()
		{
			return gcnew RNGCryptoServiceProvider();
		}
		static const int NonceTries = 1000;// give up after 1000 tries - obviously something ELSE is wrong other than a nonce.
		static String ^PrivateKeyLengthError = "Private key must be 32 bytes long.";
		static String ^CompactsignaturenatureLengthError = "Compact signaturenatures must be 64 bytes long.";
	public:
		enum class VerifyResult
		{
			/// <summary>The signature is valid.</summary>
			Verified,
			/// <summary>The signature is not a match for this data.</summary>
			SignatureFailed,
			/// <summary>An invalid public key was provided.</summary>
			InvalidPublicKey,
			/// <summary>An invalid signature was provided.</summary>
			InvalidSignature,
			/// <summary>An unknown error has occurred.</summary>
			Error
		};
		/// <summary>Verifies that a signature is valid.</summary>
		/// <param name="message">The message to verify.  This data is not hashed.  For use with bitcoins, you probably want to double-SHA256 hash this before calling this method.</param>
		/// <param name="signature">The signature to test for validity. This must not be a compact key (Use RecoverKeyFromCompact instead).</param>
		/// <param name="publicKey">The public key used to create the signature.</param>
		static VerifyResult Verify(array<Byte> ^message, array<Byte> ^signature, array<Byte> ^publicKey)
		{
			if (message == nullptr || signature == nullptr || publicKey == nullptr)
				throw gcnew ArgumentNullException();
			pin_ptr<Byte> messageptr = &message[0];
			pin_ptr<Byte> signatureptr = &signature[0];
			pin_ptr<Byte> keyptr = &publicKey[0];
			int result = secp256k1_ecdsa_verify(messageptr, message->Length, signatureptr, signature->Length, keyptr, publicKey->Length);
			switch (result)
			{
			case 1:
				return VerifyResult::Verified;
			case 0:
				return VerifyResult::SignatureFailed;
			case - 1:
				return VerifyResult::InvalidPublicKey;
			case - 2:
				return VerifyResult::InvalidSignature;
			default:
				return VerifyResult::Error;
			}
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
			pin_ptr<Byte> messageptr = &message[0];
			pin_ptr<Byte> keyptr = &privateKey[0];
			array<Byte> ^nonce = gcnew array<Byte>(32);
			pin_ptr<Byte> nonceptr = &nonce[0];
			array<Byte> ^signature = gcnew array<Byte>(72);
			pin_ptr<Byte> signatureptr = &signature[0];
			int signaturelen = signature->Length;
			pin_ptr<int> siglenptr = &signaturelen;
			for (int x = 0; x < NonceTries; ++x)
			{
				Randoms->Value->GetBytes(nonce);
				int result = secp256k1_ecdsa_sign(messageptr, message->Length, signatureptr, siglenptr, keyptr, nonceptr);
				if (result == 1)
				{
					if (signaturelen == signature->Length)
						return signature;
					array<Byte> ^smallsignature = gcnew array<Byte>(signaturelen);
					array<Byte>::Copy(signature, 0, smallsignature, 0, signaturelen);
					return smallsignature;
				}
			}
			return nullptr;
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
			recoveryId = 0;
			pin_ptr<Byte> messageptr = &message[0];
			pin_ptr<Byte> keyptr = &privateKey[0];
			array<Byte> ^nonce = gcnew array<Byte>(32);
			pin_ptr<Byte> nonceptr = &nonce[0];
			array<Byte> ^signature = gcnew array<Byte>(64);
			pin_ptr<Byte> signatureptr = &signature[0];
			int recid;
			pin_ptr<int> recidptr = &recid;
			for (int x = 0; x < NonceTries; ++x)
			{
				Randoms->Value->GetBytes(nonce);
				int result = secp256k1_ecdsa_sign_compact(messageptr, message->Length, signatureptr, keyptr, nonceptr, recidptr);
				if (result == 1)
				{
					recoveryId = recid;
					return signature;
				}
			}
			return nullptr;
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
				throw gcnew ArgumentOutOfRangeException(CompactsignaturenatureLengthError);
			pin_ptr<Byte> messageptr = &message[0];
			pin_ptr<Byte> signatureptr = &signature[0];
			array<Byte> ^key = gcnew array<Byte>(65);
			pin_ptr<Byte> keyptr = &key[0];
			int keylen = key->Length;
			pin_ptr<int> keylenptr = &keylen;
			int result = secp256k1_ecdsa_recover_compact(messageptr, message->Length, signatureptr, keyptr, keylenptr, compressed ? 1 : 0, recoveryId);
			if (result == 1)
			{
				if (keylen == key->Length)
					return key;
				array<Byte> ^smallkey = gcnew array<Byte>(keylen);
				array<Byte>::Copy(key, 0, smallkey, 0, keylen);
				return smallkey;
			}
			return nullptr;
		}
		/// <summary>Verifies that a private key is valid.  Returns true if valid.</summary>
		/// <param name="privateKey">A private key to test for validity.</param>
		static bool VerifyPrivateKey(array<Byte> ^privateKey)
		{
			if (privateKey == nullptr || privateKey->Length != 32)
				return false;
			pin_ptr<Byte> keyptr = &privateKey[0];
			return secp256k1_ecdsa_seckey_verify(keyptr) == 1;
		}
		/// <summary>Verifies that a public key is valid.</summary>
		/// <param name="publicKey">A public key to test for validity.</param>
		static bool VerifyPublicKey(array<Byte> ^publicKey)
		{
			if (publicKey == nullptr)
				return false;
			pin_ptr<Byte> keyptr = &publicKey[0];
			return secp256k1_ecdsa_pubkey_verify(keyptr, publicKey->Length) == 1;
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
			pin_ptr<Byte> privateKeyptr = &privateKey[0];
			array<Byte> ^publicKey = gcnew array<Byte>(compressed ? 33 : 65);
			pin_ptr<Byte> publicKeyptr = &publicKey[0];
			int publicKeylen = publicKey->Length;
			pin_ptr<int> publickeylenptr = &publicKeylen;
			int result = secp256k1_ecdsa_pubkey_create(publicKeyptr, publickeylenptr, privateKeyptr, compressed ? 1 : 0);
			if (result == 1)
			{
				if (publicKeylen == publicKey->Length)
					return publicKey;
				array<Byte> ^smallkey = gcnew array<Byte>(publicKeylen);
				array<Byte>::Copy(publicKey, 0, smallkey, 0, publicKeylen);
				return smallkey;
			}
			return nullptr;
		}
	};
};