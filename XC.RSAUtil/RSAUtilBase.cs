using System;
using System.Security.Cryptography;
using System.Text;

namespace XC.RSAUtil
{
	public abstract class RSAUtilBase:IDisposable
	{
		public RSA PrivateRsa;
		public RSA PublicRsa;
		public Encoding DataEncoding;

		/// <summary>
		/// RSA public key encryption
		/// </summary>
		/// <param name="data">Need to encrypt data</param>
		/// <param name="padding">Padding algorithm</param>
		/// <returns></returns>
		public string Encrypt(string data, RSAEncryptionPadding padding)
		{
			if (PublicRsa == null)
			{
				throw new ArgumentException("public key can not null");
			}
			byte[] dataBytes = DataEncoding.GetBytes(data);
			var resBytes = PublicRsa.Encrypt(dataBytes, padding);
			return Convert.ToBase64String(resBytes);
		}

		/// <summary>
		/// RSA private key is decrypted
		/// </summary>
		/// <param name="data">Need to decrypt the data</param>
		/// <param name="padding">Padding algorithm</param>
		/// <returns></returns>
		public string Decrypt(string data, RSAEncryptionPadding padding)
		{
			if (PrivateRsa == null)
			{
				throw new ArgumentException("private key can not null");
			}
			byte[] dataBytes = Convert.FromBase64String(data);
			var resBytes = PrivateRsa.Decrypt(dataBytes, padding);
			return DataEncoding.GetString(resBytes);
		}

		/// <summary>
		/// Use private key for data signing
		/// </summary>
		/// <param name="data">Need to sign data</param>
		/// <param name="hashAlgorithmName">Signed hash algorithm name</param>
		/// <param name="padding">Signature padding algorithm</param>
		/// <returns></returns>
		public string SignData(string data, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
		{
		    var res = SignDataGetBytes(data, hashAlgorithmName, padding);
            return Convert.ToBase64String(res);
		}

	    /// <summary>
	    /// Use private key for data signing
	    /// </summary>
	    /// <param name="data">Need to sign data</param>
	    /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
	    /// <param name="padding">Signature padding algorithm</param>
	    /// <returns>Sign bytes</returns>
	    public byte[] SignDataGetBytes(string data, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
	    {
	        if (PrivateRsa == null)
	        {
	            throw new ArgumentException("private key can not null");
	        }
	        var dataBytes = DataEncoding.GetBytes(data);
	        return PrivateRsa.SignData(dataBytes, hashAlgorithmName, padding);
	    }

        /// <summary>
        /// Use public key to verify data signature
        /// </summary>
        /// <param name="data">Need to verify the signature data</param>
        /// <param name="sign">sign</param>
        /// <param name="hashAlgorithmName">Signed hash algorithm name</param>
        /// <param name="padding">Signature padding algorithm</param>
        /// <returns></returns>
        public bool VerifyData(string data, string sign, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
		{
			if (PublicRsa == null)
			{
				throw new ArgumentException("public key can not null");
			}
			var dataBytes = DataEncoding.GetBytes(data);
			var signBytes = Convert.FromBase64String(sign);
			var res = PublicRsa.VerifyData(dataBytes, signBytes, hashAlgorithmName, padding);
			return res;
		}

		protected abstract RSAParameters CreateRsapFromPrivateKey(string privateKey);
		protected abstract RSAParameters CreateRsapFromPublicKey(string publicKey);

        public void Dispose()
        {
            PrivateRsa?.Dispose();
            PublicRsa?.Dispose();
        }
    }
}