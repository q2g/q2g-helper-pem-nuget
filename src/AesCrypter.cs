namespace Q2g.HelperPem
{
    #region Usings
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    #endregion

    public class AesCrypter
    {
        #region Properties
        private PemSigner Signer { get; set; }
        private string Key { get; set; }
        #endregion

        #region Constructor
        public AesCrypter(string keyPath)
        {
            Signer = new PemSigner(keyPath);
            Key = GetShortHash();
        }
        #endregion

        #region Private Methods
        private string GetShortHash()
        {
            var hash = GetHashString(Signer.GetHashFromTextWithPrivateKey("b14ca58a8a4e4133b1ce2ea2315a191f"));
            return hash.Substring(0, 32);
        }

        private static byte[] GetHash(string inputString)
        {
            using (HashAlgorithm algorithm = SHA256.Create())
            {
                return algorithm.ComputeHash(Encoding.UTF8.GetBytes(inputString));
            }
        }

        private static string GetHashString(string inputString)
        {
            var sb = new StringBuilder();
            foreach (byte b in GetHash(inputString))
                sb.Append(b.ToString("X2"));
            return sb.ToString();
        }
        #endregion

        #region Public Methods
        public string EncryptText(string value)
        {
            try
            {
                var iv = new byte[16];
                using (var aes = Aes.Create())
                {
                    aes.BlockSize = 128;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Mode = CipherMode.CBC;
                    aes.KeySize = 256;
                    aes.Key = Encoding.UTF8.GetBytes(Key);
                    aes.IV = iv;
                    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    using (var memoryStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            using (var streamWriter = new StreamWriter(cryptoStream))
                                streamWriter.Write(value);
                            var array = memoryStream.ToArray();
                            return Convert.ToBase64String(array);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("The text could not be encrypt.", ex);
            }
        }

        public string DecryptText(string value)
        {
            try
            {
                var iv = new byte[16];
                var buffer = Convert.FromBase64String(value);
                using (var aes = Aes.Create())
                {
                    aes.BlockSize = 128;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Mode = CipherMode.CBC;
                    aes.KeySize = 256;
                    aes.IV = iv;
                    aes.Key = Encoding.UTF8.GetBytes(Key);
                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    using (var memoryStream = new MemoryStream(buffer))
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (var streamReader = new StreamReader(cryptoStream))
                            {
                                return streamReader.ReadToEnd();
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("The base64 text could not decrypt.", ex);
            }
        }
        #endregion
    }
}