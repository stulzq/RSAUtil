using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace XC.RSAUtil
{
    /// <summary>
    /// RSA pkcs8 format key helper class
    /// Author:Zhiqiang Li
    /// </summary>
    public class RsaPkcs8Util:RSAUtilBase
    {
        public RsaPkcs8Util(Encoding dataEncoding, string publicKey, string privateKey = null, int keySize = 2048)
        {
            if (string.IsNullOrEmpty(privateKey) && string.IsNullOrEmpty(publicKey))
            {
                throw new Exception("Public and private keys must not be empty at the same time");
            }

            if (!string.IsNullOrEmpty(privateKey))
            {
                PrivateRsa = RSA.Create();
                PrivateRsa.KeySize = keySize;
                var priRsap = CreateRsapFromPrivateKey(privateKey);
                PrivateRsa.ImportParameters(priRsap);

                if (string.IsNullOrEmpty(publicKey))
                {
                    PublicRsa = RSA.Create();
                    PublicRsa.KeySize = keySize;
                    var pubRsap = new RSAParameters
                    {
                        Modulus = priRsap.Modulus,
                        Exponent = priRsap.Exponent
                    };
                    PublicRsa.ImportParameters(pubRsap);
                }
            }

            if (!string.IsNullOrEmpty(publicKey))
            {
                PublicRsa = RSA.Create();
                PublicRsa.KeySize = keySize;
                var pubRsap = CreateRsapFromPublicKey(publicKey);
                PublicRsa.ImportParameters(pubRsap);
            }

            DataEncoding = dataEncoding ?? Encoding.UTF8;
        }

		/// <summary>
		/// Create an RSA parameter based on the xml format public key
		/// </summary>
		/// <param name="publicKey"></param>
		/// <returns></returns>
		protected sealed override RSAParameters CreateRsapFromPublicKey(string publicKey)
        {
            publicKey = RsaPemFormatHelper.PublicKeyFormatRemove(publicKey);
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            var rsap = new RSAParameters();
            rsap.Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();
            rsap.Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();
            return rsap;
        }

		/// <summary>
		/// Create an RSA parameter based on the xml format private key
		/// </summary>
		/// <param name="privateKey"></param>
		/// <returns></returns>
		protected sealed override RSAParameters CreateRsapFromPrivateKey(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs8PrivateKeyFormatRemove(privateKey);
            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

            var rsap=new RSAParameters();
            rsap.Modulus = privateKeyParam.Modulus.ToByteArrayUnsigned();
            rsap.Exponent = privateKeyParam.PublicExponent.ToByteArrayUnsigned();
            rsap.P = privateKeyParam.P.ToByteArrayUnsigned();
            rsap.Q = privateKeyParam.Q.ToByteArrayUnsigned();
            rsap.DP = privateKeyParam.DP.ToByteArrayUnsigned();
            rsap.DQ = privateKeyParam.DQ.ToByteArrayUnsigned();
            rsap.InverseQ = privateKeyParam.QInv.ToByteArrayUnsigned();
            rsap.D = privateKeyParam.Exponent.ToByteArrayUnsigned();

            return rsap;
        }

    }
}