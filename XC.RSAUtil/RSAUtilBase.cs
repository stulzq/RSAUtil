using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace XC.RSAUtil
{
    public abstract class RSAUtilBase : IDisposable
    {
        public RSA PrivateRsa;
        public RSA PublicRsa;
        public Encoding DataEncoding;

        static readonly Dictionary<RSAEncryptionPadding, int> PaddingLimitDic = new Dictionary<RSAEncryptionPadding, int>()
        {
            [RSAEncryptionPadding.Pkcs1] = 11,
            [RSAEncryptionPadding.OaepSHA1] = 42,
            [RSAEncryptionPadding.OaepSHA256] = 66,
            [RSAEncryptionPadding.OaepSHA384] = 98,
            [RSAEncryptionPadding.OaepSHA512] = 130,
        };

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
        /// <param name="dataStr">Need to encrypt data</param>
        /// <param name="connChar">Encrypted result link character</param>
        /// <param name="padding">Padding algorithm</param>
        /// <returns></returns>
        public string EncryptBigData(string dataStr, RSAEncryptionPadding padding, char connChar = '$')
        {
            var data = Encoding.UTF8.GetBytes(dataStr);
            var modulusLength = PublicRsa.KeySize / 8;
            var splitLength = modulusLength - PaddingLimitDic[padding];

            var sb = new StringBuilder();

            var splitsNumber = Convert.ToInt32(Math.Ceiling(data.Length * 1.0 / splitLength));

            var pointer = 0;
            for (int i = 0; i < splitsNumber; i++)
            {
                byte[] current = pointer + splitLength < data.Length ? data.Skip(pointer).Take(splitLength).ToArray() : data.Skip(pointer).Take(data.Length - pointer).ToArray();

                sb.Append(Convert.ToBase64String(PublicRsa.Encrypt(current, padding)));
                sb.Append(connChar);
                pointer += splitLength;
            }

            return sb.ToString().TrimEnd(connChar);
        }
        /// <summary>
        /// RSA 无长度限制 公钥加密
        /// </summary>
        /// <param name="dataStr">需要加密的数据</param>
        /// <param name="padding">填充算法</param>
        /// <returns></returns>
        public string RsaEncrypt(string dataStr, RSAEncryptionPadding padding)
        {
            if (string.IsNullOrEmpty(dataStr)) return string.Empty;
            if (PublicRsa == null) throw new ArgumentException("public key can not null");
            var inputBytes = DataEncoding.GetBytes(dataStr);
            int bufferSize = (PublicRsa.KeySize / 8) - 11;//单块最大长度
            var buffer = new byte[bufferSize];
            using (MemoryStream inputStream = new MemoryStream(inputBytes), outputStream = new MemoryStream())
            {
                while (true)//分段加密
                {
                    int readSize = inputStream.Read(buffer, 0, bufferSize);
                    if (readSize <= 0) break;
                    var temp = new byte[readSize];
                    Array.Copy(buffer, 0, temp, 0, readSize);
                    var encryptedBytes = PublicRsa.Encrypt(temp, padding);
                    outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                }
                return Convert.ToBase64String(outputStream.ToArray());
            }
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
        /// <param name="dataStr">Need to decrypt the data</param>
        /// <param name="padding">Padding algorithm</param>
        /// <returns></returns>
        public string DecryptBigData(string dataStr, RSAEncryptionPadding padding, char connChar = '$')
        {
            if (PrivateRsa == null)
            {
                throw new ArgumentException("private key can not null");
            }

            var data = dataStr.Split(new[] { connChar }, StringSplitOptions.RemoveEmptyEntries);
            var byteList = new List<byte>();

            foreach (var item in data)
            {
                byteList.AddRange(PrivateRsa.Decrypt(Convert.FromBase64String(item), padding));
            }

            return Encoding.UTF8.GetString(byteList.ToArray());
        }
        /// <summary>
        /// RSA 无长度限制 私钥解密
        /// </summary>
        /// <param name="dataStr">需要解密的数据</param>
        /// <param name="padding">填充算法</param>
        /// <returns></returns>
        public string RsaDecrypt(string dataStr, RSAEncryptionPadding padding)
        {
            if (string.IsNullOrEmpty(dataStr)) return string.Empty;
            if (PrivateRsa == null) throw new ArgumentException("private key can not null");
            var inputBytes = Convert.FromBase64String(dataStr);
            int bufferSize = PrivateRsa.KeySize / 8;
            var buffer = new byte[bufferSize];
            using (MemoryStream inputStream = new MemoryStream(inputBytes), outputStream = new MemoryStream())
            {
                while (true)
                {
                    int readSize = inputStream.Read(buffer, 0, bufferSize);
                    if (readSize <= 0) break;
                    var temp = new byte[readSize];
                    Array.Copy(buffer, 0, temp, 0, readSize);
                    var rawBytes = PrivateRsa.Decrypt(temp, padding);
                    outputStream.Write(rawBytes, 0, rawBytes.Length);
                }
                return Encoding.UTF8.GetString(outputStream.ToArray());
            }
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