using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace XC.RSAUtil
{
    /// <summary>
    /// .net core xml format The RSA key helper classes are compatible with the xml formatted keys used by the .NET Framework
    /// Author:Zhiqiang Li
    /// CreateDate:2018-1-5
    /// </summary>
    public class RsaXmlUtil:RSAUtilBase
    {
        /// <summary>
        /// RSA encryption
        /// SHA256 hash algorithm to use the key length of at least 2048
        /// </summary>
        /// <param name="dataEncoding">Data coding</param>
        /// <param name="keySize">Key length in bits:</param>
        /// <param name="privateKey">private Key</param>
        /// <param name="publicKey">public Key</param>
        public RsaXmlUtil(Encoding dataEncoding,string publicKey, string privateKey = null, int keySize = 2048)
        {
            if (string.IsNullOrEmpty(privateKey) && string.IsNullOrEmpty(publicKey))
            {
               throw new ArgumentException("Public and private keys must not be empty at the same time");
            }
            else
            {
                RSAParameters pubRsap;
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
                        pubRsap = new RSAParameters
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
                    pubRsap = CreateRsapFromPublicKey(publicKey);
                    PublicRsa.KeySize = keySize;
                    PublicRsa.ImportParameters(pubRsap );
                }
            }
            

            DataEncoding = dataEncoding ?? Encoding.UTF8;
        }

        /// <summary>
        /// Create an RSA parameter based on the xml format private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        protected sealed override RSAParameters CreateRsapFromPrivateKey(string privateKey)
        {
            var rsap=new RSAParameters();
            try
            {
                XElement root = XElement.Parse(privateKey);
                //Modulus
                var modulus = root.Element("Modulus");
                //Exponent
                var exponent = root.Element("Exponent");
                //P
                var p = root.Element("P");
                //Q
                var q = root.Element("Q");
                //DP
                var dp = root.Element("DP");
                //DQ
                var dq = root.Element("DQ");
                //InverseQ
                var inverseQ = root.Element("InverseQ");
                //D
                var d = root.Element("D");

                rsap.Modulus = Convert.FromBase64String(modulus.Value);
                rsap.Exponent = Convert.FromBase64String(exponent.Value);
                rsap.P = Convert.FromBase64String(p.Value);
                rsap.Q = Convert.FromBase64String(q.Value);
                rsap.DP = Convert.FromBase64String(dp.Value);
                rsap.DQ = Convert.FromBase64String(dq.Value);
                rsap.InverseQ = Convert.FromBase64String(inverseQ.Value);
                rsap.D = Convert.FromBase64String(d.Value);
                return rsap;
            }
            catch (Exception e)
            {
                throw new Exception("Private key format is incorrect",e);
            }
            
        }

		/// <summary>
		/// Create an RSA parameter based on the xml format public key
		/// </summary>
		/// <param name="publicKey"></param>
		/// <returns></returns>
		protected sealed override RSAParameters CreateRsapFromPublicKey( string publicKey)
        {
            var rsap = new RSAParameters();
            try
            {
                XElement root = XElement.Parse(publicKey);
                //Modulus
                var modulus = root.Element("Modulus");
                //Exponent
                var exponent = root.Element("Exponent");

                rsap.Modulus = Convert.FromBase64String(modulus.Value);
                rsap.Exponent = Convert.FromBase64String(exponent.Value);
            }
            catch (Exception e)
            {
                throw new Exception("Public key format is incorrect", e);
            }
            return rsap;
        }
    }
}