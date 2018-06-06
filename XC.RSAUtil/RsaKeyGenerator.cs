using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace XC.RSAUtil
{
    /// <summary>
    ///  Rsa Key Generator
    /// Author:Zhiqiang Li
    /// </summary>
    public class RsaKeyGenerator
    {
        /// <summary>
        /// Generate XML Format RSA Key. Result: Index 0 is the private key and index 1 is the public key
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <returns></returns>
        public static List<string> XmlKey(int keySize)
        {
            RSA rsa = RSA.Create();
            rsa.KeySize = keySize;
            var rsap = rsa.ExportParameters(true);
            List<string> res = new List<string>();

            XElement privatElement = new XElement("RSAKeyValue");
            //Modulus
            XElement primodulus = new XElement("Modulus", Convert.ToBase64String(rsap.Modulus));
            //Exponent
            XElement priexponent = new XElement("Exponent", Convert.ToBase64String(rsap.Exponent));
            //P
            XElement prip = new XElement("P", Convert.ToBase64String(rsap.P));
            //Q
            XElement priq = new XElement("Q", Convert.ToBase64String(rsap.Q));
            //DP
            XElement pridp = new XElement("DP", Convert.ToBase64String(rsap.DP));
            //DQ
            XElement pridq = new XElement("DQ", Convert.ToBase64String(rsap.DQ));
            //InverseQ
            XElement priinverseQ = new XElement("InverseQ", Convert.ToBase64String(rsap.InverseQ));
            //D
            XElement prid = new XElement("D", Convert.ToBase64String(rsap.D));

            privatElement.Add(primodulus);
            privatElement.Add(priexponent);
            privatElement.Add(prip);
            privatElement.Add(priq);
            privatElement.Add(pridp);
            privatElement.Add(pridq);
            privatElement.Add(priinverseQ);
            privatElement.Add(prid);
            
            //添加私钥
            res.Add(privatElement.ToString());


            XElement publicElement = new XElement("RSAKeyValue");
            //Modulus
            XElement pubmodulus = new XElement("Modulus", Convert.ToBase64String(rsap.Modulus));
            //Exponent
            XElement pubexponent = new XElement("Exponent", Convert.ToBase64String(rsap.Exponent));

            publicElement.Add(pubmodulus);
            publicElement.Add(pubexponent);

            //添加公钥
            res.Add(publicElement.ToString());

            return res;
        }

        /// <summary>
        /// Generate RSA key in Pkcs1 format. Result: Index 0 is the private key and index 1 is the public key
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="format">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static List<string> Pkcs1Key(int keySize,bool format)
        {
            List<string> res = new List<string>();

            IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
            var keyPair = kpGen.GenerateKeyPair();

            StringWriter sw = new StringWriter();
            PemWriter pWrt = new PemWriter(sw);
            pWrt.WriteObject(keyPair.Private);
            pWrt.Writer.Close();
            var privateKey = sw.ToString();

            if (!format)
            {
                privateKey = privateKey.Replace("-----BEGIN RSA PRIVATE KEY-----", "").Replace("-----END RSA PRIVATE KEY-----", "").Replace("\r\n", "");
            }

            res.Add(privateKey);

            StringWriter swpub = new StringWriter();
            PemWriter pWrtpub = new PemWriter(swpub);
            pWrtpub.WriteObject(keyPair.Public);
            pWrtpub.Writer.Close();
            string publicKey = swpub.ToString();
            if (!format)
            {
                publicKey = publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\r\n", "");
            }

            res.Add(publicKey);

            return res;
        }

        /// <summary>
        /// Generate Pkcs8 format RSA key. Result: Index 0 is the private key and index 1 is the public key
        /// </summary>
        /// <param name="keySize">Key Size.Unit: bits</param>
        /// <param name="format">Whether the format is true If it is standard pem file format</param>
        /// <returns></returns>
        public static List<string> Pkcs8Key(int keySize, bool format)
        {
            List<string> res = new List<string>();

            IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
            var keyPair = kpGen.GenerateKeyPair();

            StringWriter swpri = new StringWriter();
            PemWriter pWrtpri = new PemWriter(swpri);
            Pkcs8Generator pkcs8 = new Pkcs8Generator(keyPair.Private);
            pWrtpri.WriteObject(pkcs8);
            pWrtpri.Writer.Close();
            string privateKey = swpri.ToString();

            if (!format)
            {
                privateKey = privateKey.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace("\r\n", "");
            }

            res.Add(privateKey);

            StringWriter swpub = new StringWriter();
            PemWriter pWrtpub = new PemWriter(swpub);
            pWrtpub.WriteObject(keyPair.Public);
            pWrtpub.Writer.Close();
            string publicKey = swpub.ToString();
            if (!format)
            {
                publicKey = publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\r\n", "");
            }

            res.Add(publicKey);

            return res;
        }
    }
}