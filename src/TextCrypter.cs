﻿namespace Q2g.HelperPem
{
    #region Usings
    using System;
    using System.Text;
    #endregion

    public class TextCrypter : CryptoBase
    {
        public TextCrypter()
        {
            GenerateKeys();
        }

        public TextCrypter(string keyPath)
        {
            ReadKey(keyPath);
        }

        public string EncryptText(string text)
        {
            try
            {
                var rsaProvider = GetRsaProvider();
                var data = Encoding.UTF8.GetBytes(text);
                var encryptedData = rsaProvider.Encrypt(data, true);
                var base64Encrypted = Convert.ToBase64String(encryptedData);
                return base64Encrypted;
            }
            catch (Exception ex)
            {
                throw new Exception("The text could not be encrypt.", ex);
            }
        }

        public string DecryptText(string base64EncryptedText)
        {
            try
            {
                if (!HasPrivateKey)
                    throw new Exception("No private key found.");

                var rsaProvider = GetRsaProvider();
                var resultBytes = Convert.FromBase64String(base64EncryptedText);
                var decryptedBytes = rsaProvider.Decrypt(resultBytes, true);
                var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
                return decryptedData.ToString();
            }
            catch (Exception ex)
            {
                throw new Exception("The base64 text could not decrypt.", ex);
            }
        }

        public void SavePrivateKey(string path)
        {
            try
            {
                SaveKey(path, PrivateKey);
            }
            catch (Exception ex)
            {
                throw new Exception("The private key could not saved.", ex);
            }
        }

        public void SavePublicKey(string path)
        {
            try
            {
                SaveKey(path, PublicKey);
            }
            catch (Exception ex)
            {
                throw new Exception("The public key could not saved.", ex);
            }
        }
    }
}
