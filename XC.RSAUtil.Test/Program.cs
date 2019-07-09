using System;
using System.Security.Cryptography;
using System.Text;

namespace XC.RSAUtil.Test
{
    class Program
    {
        static void Main(string[] args)
        {

			Console.WriteLine(RsaKeyGenerator.XmlKey(2048)[0]);
            Console.WriteLine(RsaKeyGenerator.Pkcs1Key(2048,true)[0]);
            Console.WriteLine(RsaKeyGenerator.Pkcs8Key(2048,true)[0]);


            Console.WriteLine("Key Convert:");
            var keyList = RsaKeyGenerator.Pkcs1Key(2048, false);
            var privateKey = keyList[0];
            var publicKey = keyList[1];
            Console.WriteLine("public key pkcs1->xml:");
            Console.WriteLine(RsaKeyConvert.PublicKeyPemToXml(publicKey));

            var bigDataRsa=new RsaPkcs1Util(Encoding.UTF8, publicKey,privateKey,2048);
            var str = bigDataRsa.EncryptBigData("abcdefg", 3, "$", RSAEncryptionPadding.Pkcs1);
            Console.WriteLine("Big Data Encrypt:");
            Console.WriteLine(str);
            Console.WriteLine("Big Data Decrypt:");
            Console.WriteLine(string.Join("", bigDataRsa.DecryptBigData(str, "$", RSAEncryptionPadding.Pkcs1)));

            Console.ReadKey();
        }
    }
}
