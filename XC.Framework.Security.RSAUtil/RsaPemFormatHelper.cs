using System.Collections.Generic;

namespace XC.Framework.Security.RSAUtil
{
    public class RsaPemFormatHelper
    {
        /// <summary>
        /// Format Pkcs1 format private key
        /// Author:Zhiqiang Li
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Pkcs1PrivateKeyFormat(string str)
        {
            if (str.StartsWith("-----BEGIN RSA PRIVATE KEY-----"))
            {
                return str;
            }

            List<string> res = new List<string>();
            res.Add("-----BEGIN RSA PRIVATE KEY-----");

            int pos = 0;

            while (pos<str.Length)
            {
                var count = str.Length - pos<64? str.Length - pos:64;
                res.Add(str.Substring(pos, count));
                pos += count;
            }

            res.Add("-----END RSA PRIVATE KEY-----");
            var resStr = string.Join("\r\n", res);
            return resStr;
        }

        /// <summary>
        /// Remove the Pkcs1 format private key format
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Pkcs1PrivateKeyFormatRemove(string str)
        {
            if (!str.StartsWith("-----BEGIN RSA PRIVATE KEY-----"))
            {
                return str;
            }
            return str.Replace("-----BEGIN RSA PRIVATE KEY-----", "").Replace("-----END RSA PRIVATE KEY-----", "")
                .Replace("\r\n", "");
        }

        /// <summary>
        /// Format Pkcs8 format private key
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Pkcs8PrivateKeyFormat(string str)
        {
            if (str.StartsWith("-----BEGIN PRIVATE KEY-----"))
            {
                return str;
            }
            List<string> res = new List<string>();
            res.Add("-----BEGIN PRIVATE KEY-----");

            int pos = 0;

            while (pos < str.Length)
            {
                var count = str.Length - pos < 64 ? str.Length - pos : 64;
                res.Add(str.Substring(pos, count));
                pos += count;
            }

            res.Add("-----END PRIVATE KEY-----");
            var resStr = string.Join("\r\n", res);
            return resStr;
        }

        /// <summary>
        /// Remove the Pkcs8 format private key format
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Pkcs8PrivateKeyFormatRemove(string str)
        {
            if (!str.StartsWith("-----BEGIN PRIVATE KEY-----"))
            {
                return str;
            }
            return str.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "")
                .Replace("\r\n", "");
        }

        /// <summary>
        /// Format public key
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string PublicKeyFormat(string str)
        {
            if (str.StartsWith("-----BEGIN PUBLIC KEY-----"))
            {
                return str;
            }
            List<string> res = new List<string>();
            res.Add("-----BEGIN PUBLIC KEY-----");
            int pos = 0;

            while (pos < str.Length)
            {
                var count = str.Length - pos < 64 ? str.Length - pos : 64;
                res.Add(str.Substring(pos, count));
                pos += count;
            }
            res.Add("-----END PUBLIC KEY-----");
            var resStr = string.Join("\r\n", res);
            return resStr;
        }

        /// <summary>
        /// Public key format removed
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string PublicKeyFormatRemove(string str)
        {
            if (!str.StartsWith("-----BEGIN PUBLIC KEY-----"))
            {
                return str;
            }
            return str.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "")
                .Replace("\r\n", "");
        }
    }
}