using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using XC.Framework.Security.RSAUtil;

namespace XC.Framework.Security.Test
{
    class Program
    {
        static void Main(string[] args)
        {
	        var keyList = RsaKeyGenerator.XmlKey(2048);
	        var privateKey = keyList[0];
	        var publicKey = keyList[1];

			Console.WriteLine(RsaKeyGenerator.XmlKey(2048)[0]);
            Console.WriteLine(RsaKeyGenerator.Pkcs1Key(2048,true)[0]);
            Console.WriteLine(RsaKeyGenerator.Pkcs8Key(2048,true)[0]);

            Console.ReadKey();
        }
    }
}
