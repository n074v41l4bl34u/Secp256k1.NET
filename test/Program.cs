using Secp256k1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace test
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                byte[] priv = new byte[32];
                priv[1] = 2;
                bool ok = Proxy.VerifyPrivateKey(priv);
                byte[] sig = Proxy.Sign(priv, priv);
                byte[] pub = Proxy.GetPublicKey(priv, true);
                byte[] pub2 = Proxy.GetPublicKey(priv, false);
                ok = Proxy.Verify(priv, sig, pub);
                ok = Proxy.Verify(priv, sig, pub2);
                int rec;
                sig = Proxy.SignCompact(priv, priv, out rec);
                byte[] pub3 = Proxy.RecoverKeyFromCompact(priv, sig, rec, true);
                byte[] pub4 = Proxy.RecoverKeyFromCompact(priv, sig, rec, false);
                Console.WriteLine(ok);
                Console.ReadLine();
            }
            catch (Exception e)
            {
            }
        }
    }
}
