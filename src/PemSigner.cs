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
                using (var reader = new StreamReader(public_key_path, Encoding.ASCII))
                {
                    var pemReader = new PemReader(reader);
                    return pemReader.ReadObject() as RsaKeyParameters;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"The public key {public_key_path} could not read.", ex);
            }
        }

        public bool IsValidPublicKey(string data, string sign, string algorithm = "SHA256withRSA")
        {
            try
            {
                var sig = Convert.FromBase64String(sign);
                ISigner signer = SignerUtilities.GetSigner(algorithm);
                signer.Init(false, PublicKey);

                var msgBytes = Encoding.UTF8.GetBytes(data);
                signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
                return signer.VerifySignature(sig);
            }
            catch (Exception ex)
            {
                throw new Exception("The public key could not be properly verified.", ex);
            }
        }

        public string SignWithPrivateKey(string data, bool write_algo_as_prefix = false, bool use_indent = false, string algorithm = "SHA256")
        {
            try
            {
                var rsa = RSA.Create() as RSACryptoServiceProvider;
                var rsaParameters = PemUtils.ToRSAParameters(PrivateKey);
                rsa.ImportParameters(rsaParameters);

                var sha = new SHA256CryptoServiceProvider();
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(data));
                var id = CryptoConfig.MapNameToOID(algorithm);
                var sig = rsa.SignHash(hash, id);

                var prefix = String.Empty;
                if (write_algo_as_prefix)
                    prefix = $"{algorithm}:\n";

                if (use_indent)
                    return prefix + Convert.ToBase64String(sig, Base64FormattingOptions.InsertLineBreaks);

                return prefix + Convert.ToBase64String(sig);
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