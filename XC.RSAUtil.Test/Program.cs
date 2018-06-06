using System;

namespace XC.RSAUtil.Test
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
