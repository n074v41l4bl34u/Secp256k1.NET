using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Secp256k1
{
    public static class Proxy
    {
        static Type signaturesType;
        static Type SignaturesType
        {
            get
            {
                if (signaturesType == null)
                {
                    Assembly a = Assembly.LoadFrom("Secp256k1." + (IntPtr.Size == 4 ? "x86" : "x64") + ".dll");
                    signaturesType = a.GetType("Secp256k1.Signatures");
                }
                return signaturesType;
            }
        }

        public delegate bool VerifyPrivateKeyDelegate(byte[] privateKey);
        public static VerifyPrivateKeyDelegate VerifyPrivateKey = (VerifyPrivateKeyDelegate)Delegate.CreateDelegate(typeof(VerifyPrivateKeyDelegate), SignaturesType.GetRuntimeMethod("VerifyPrivateKey", new Type[] { typeof(byte[]) }));

        public delegate bool VerifyDelegate(byte[] message, byte[] signature, byte[] publicKey);
        public static VerifyDelegate Verify = (VerifyDelegate)Delegate.CreateDelegate(typeof(VerifyDelegate), SignaturesType.GetRuntimeMethod("Verify", new Type[] { typeof(byte[]), typeof(byte[]), typeof(byte[]) }));

        public delegate byte[] SignDelegate(byte[] message, byte[] privateKey);
        public static SignDelegate Sign = (SignDelegate)Delegate.CreateDelegate(typeof(SignDelegate), SignaturesType.GetRuntimeMethod("Sign", new Type[] { typeof(byte[]), typeof(byte[]) }));

        public delegate byte[] SignCompactDelegate(byte[] message, byte[] privateKey, out int recoveryId);
        public static SignCompactDelegate SignCompact = (SignCompactDelegate)Delegate.CreateDelegate(typeof(SignCompactDelegate), SignaturesType.GetRuntimeMethod("SignCompact", new Type[] { typeof(byte[]), typeof(byte[]), typeof(int).MakeByRefType() }));

        public delegate byte[] RecoverKeyFromCompactDelegate(byte[] message, byte[] signature, int recoveryId, bool compressed);
        public static RecoverKeyFromCompactDelegate RecoverKeyFromCompact = (RecoverKeyFromCompactDelegate)Delegate.CreateDelegate(typeof(RecoverKeyFromCompactDelegate), SignaturesType.GetRuntimeMethod("RecoverKeyFromCompact", new Type[] { typeof(byte[]), typeof(byte[]), typeof(int), typeof(bool) }));

        public delegate byte[] GetPublicKeyDelegate(byte[] privateKey, bool compressed);
        public static GetPublicKeyDelegate GetPublicKey = (GetPublicKeyDelegate)Delegate.CreateDelegate(typeof(GetPublicKeyDelegate), SignaturesType.GetRuntimeMethod("GetPublicKey", new Type[] { typeof(byte[]), typeof(bool) }));
    }
}
