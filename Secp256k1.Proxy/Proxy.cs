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
        public static readonly bool Ok = Init();

        static MethodInfo VerifyMethod;
        static MethodInfo SignMethod;
        static MethodInfo SignCompactMethod;
        static MethodInfo RecoverKeyFromCompactMethod;
        static MethodInfo VerifyPrivateKeyMethod;
        static MethodInfo GetPublicKeyMethod;

        static bool Init()
        {
            Assembly a = Assembly.LoadFrom("Secp256k1." + (IntPtr.Size == 4 ? "x86" : "x64") + ".dll");
            var t = a.GetType("Secp256k1.Signatures");
            VerifyMethod = t.GetRuntimeMethod("Verify", new Type[] { typeof(byte[]), typeof(byte[]), typeof(byte[]) });
            SignMethod = t.GetRuntimeMethod("Sign", new Type[] { typeof(byte[]), typeof(byte[]) });
            SignCompactMethod = t.GetRuntimeMethod("SignCompact", new Type[] { typeof(byte[]), typeof(byte[]), typeof(int).MakeByRefType() });
            RecoverKeyFromCompactMethod = t.GetRuntimeMethod("RecoverKeyFromCompact", new Type[] { typeof(byte[]), typeof(byte[]), typeof(int), typeof(bool) });
            VerifyPrivateKeyMethod = t.GetRuntimeMethod("VerifyPrivateKey", new Type[] { typeof(byte[]) });
            GetPublicKeyMethod = t.GetRuntimeMethod("GetPublicKey", new Type[] { typeof(byte[]), typeof(bool) });
            return VerifyMethod != null && SignMethod != null && SignCompactMethod != null && RecoverKeyFromCompactMethod != null && VerifyPrivateKeyMethod != null && GetPublicKeyMethod != null;
        }

        public static bool Verify(byte[] message, byte[] signature, byte[] publicKey) => (bool)VerifyMethod.Invoke(null, new object[] { message, signature, publicKey });
        public static byte[] Sign(byte[] message, byte[] privateKey) => (byte[])SignMethod.Invoke(null, new object[] { message, privateKey });
        public static byte[] SignCompact(byte[] message, byte[] privateKey, out int recoveryId)
        {
            object[] args = new object[] { message, privateKey, 0 };
            byte[] result = (byte[])SignCompactMethod.Invoke(null, args);
            recoveryId = (int)args[2];
            return result;
        }
        public static byte[] RecoverKeyFromCompact(byte[] message, byte[] signature, int recoveryId, bool compressed) => (byte[])RecoverKeyFromCompactMethod.Invoke(null, new object[] { message, signature, recoveryId, compressed });
        public static bool VerifyPrivateKey(byte[] privateKey) => (bool)VerifyPrivateKeyMethod.Invoke(null, new object[] { privateKey });
        public static byte[] GetPublicKey(byte[] privateKey, bool compressed) => (byte[])GetPublicKeyMethod.Invoke(null, new object[] { privateKey, compressed });
    }
}
