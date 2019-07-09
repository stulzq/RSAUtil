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
        /// [Not recommended] RSA public key split encryption
        /// <para>RSA encryption does not support too large data. In this case, symmetric encryption should be used, and RSA is used to encrypt symmetrically encrypted passwords.</para>
        /// </summary>
        /// <param name="data">Need to encrypt data</param>
        /// <param name="splitLength">data split length</param>
        /// <param name="connChar">Encrypted result link character</param>
        /// <param name="padding">Padding algorithm</param>
        /// <returns></returns>
        public string EncryptBigData(string data,int splitLength,string connChar, RSAEncryptionPadding padding)
        {
            var sb=new StringBuilder();
            if (splitLength >= data.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(splitLength), "Split length cannot exceed the data length.");
            }

            var splitsNumber = Convert.ToInt32(Math.Ceiling(data.Length * 1.0 / splitLength));

            var pointer = 0;
            for (int i = 0; i < splitsNumber; i++)
            {
                string currentStr;
                if (data.Length < pointer + splitLength)
                {
                    currentStr = data.Substring(pointer, data.Length-pointer);
                }
                else
                {
                    currentStr = data.Substring(pointer, splitLength);
                }

                sb.Append(Encrypt(currentStr, padding)+connChar);
                pointer += splitLength;
            }

            return sb.ToString();
        }

        /// <summary>
        /// RSA private key  decrypted
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
        /// [Not recommended] RSA private key split decrypted
        /// <para>RSA encryption does not support too large data. In this case, symmetric encryption should be used, and RSA is used to encrypt symmetrically encrypted passwords.</para>
        /// </summary>
        /// <param name="connChar">Encrypted result link character</param>
        /// <param name="data">Need to decrypt the data</param>
        /// <param name="padding">Padding algorithm</param>
        /// <returns></returns>
        public string[] DecryptBigData(string data,string connChar, RSAEncryptionPadding padding)
        {
            if (PrivateRsa == null)
            {
                throw new ArgumentException("private key can not null");
            }

            var splitsData = data.Split(new[] {connChar}, StringSplitOptions.RemoveEmptyEntries);
            var result = new string[splitsData.Length];
            for (int i = 0; i < splitsData.Length; i++)
            {
                result[i] = Decrypt(splitsData[i], padding);
            }

            return result;
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