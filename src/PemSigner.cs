namespace Q2g.HelperPem
{
    #region Usings
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Security;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    #endregion

    public class PemSigner : CryptoBase
    {
        #region Constructor
        public PemSigner()
        {
            GenerateKeys();
        }

        public PemSigner(string keyPath)
        {
            ReadKey(keyPath);
        }

        public PemSigner(MemoryStream keyStream)
        {
            ReadKey(keyStream);
        }
        #endregion

        #region Public Methods
        public static RsaKeyParameters ReadPublicKey(string public_key_path)
        {
            try
            {
                using var reader = new StreamReader(public_key_path, Encoding.ASCII);
                var pemReader = new PemReader(reader);
                return pemReader.ReadObject() as RsaKeyParameters;
            }
            catch (Exception ex)
            {
                throw new Exception($"The public key {public_key_path} could not read.", ex);
            }
        }

        public bool ValidSignature(string data, string base64Data, HashAlgorithmName hashAlgorithm)
        {
            try
            {
                var sha = new SHA256CryptoServiceProvider();
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(data));
                var signature = Convert.FromBase64String(base64Data);
                using RSA rsa = RSA.Create();
                var rsaParameters = PemUtilsHelper.ToRSAParameters(PrivateKey);
                rsa.ImportParameters(rsaParameters);
                return rsa.VerifyHash(hash, signature, hashAlgorithm, RSASignaturePadding.Pss);
            }
            catch (Exception ex)
            {
                throw new Exception("The public key could not be properly verified.", ex);
            }
        }

        public string SignWithPrivateKey(string data, HashAlgorithmName hashAlgorithm, bool useIndent = false)
        {
            try
            {
                using RSA rsa = RSA.Create();
                var rsaParameters = PemUtilsHelper.ToRSAParameters(PrivateKey);
                rsa.ImportParameters(rsaParameters);
                var sha = new SHA256CryptoServiceProvider();
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(data));
                var signature = rsa.SignHash(hash, hashAlgorithm, RSASignaturePadding.Pss);
                if (useIndent)
                    return Convert.ToBase64String(signature, Base64FormattingOptions.InsertLineBreaks);
                return Convert.ToBase64String(signature);
            }
            catch (Exception ex)
            {
                throw new Exception("Data could not signing.", ex);
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
        #endregion
    }
}