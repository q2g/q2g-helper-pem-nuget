﻿#region License
/*
Copyright (c) 2018 Konrad Mattheis und Martin Berthold
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#endregion

namespace Q2gHelperPem
{
    #region Usings
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Crypto.Prng;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Security;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    #endregion

    public class PemSigner
    {
        #region Variables & Properties
        private AsymmetricCipherKeyPair Pair { get; set; }
        public RsaPrivateCrtKeyParameters PrivateKey { get; private set; }
        public RsaKeyParameters PublicKey { get; private set; }
        #endregion

        #region Constructor
        public PemSigner()
        {
            Pair = GetKeyPair();
            PrivateKey = Pair.Private as RsaPrivateCrtKeyParameters;
            PublicKey = Pair.Public as RsaKeyParameters;
        }

        public PemSigner(string private_key_path)
        {
            using (var reader = new StreamReader(private_key_path, Encoding.ASCII))
            {
                this.Init(reader);
            }
        }

        public PemSigner(MemoryStream private_key_stream)
        {
            using (var reader = new StreamReader(private_key_stream, Encoding.ASCII))
            {
                this.Init(reader);
            }
        }

        private void Init(StreamReader reader)
        {
            var pemReader = new PemReader(reader);
            Pair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
            PrivateKey = Pair.Private as RsaPrivateCrtKeyParameters;
            PublicKey = Pair.Public as RsaKeyParameters;
        }
        #endregion

        #region Private Methods
        private AsymmetricCipherKeyPair GetKeyPair()
        {
            var randomGenerator = new VmpcRandomGenerator();
            var secureRandom = new SecureRandom(randomGenerator);
            var keyGenerationParameters = new KeyGenerationParameters(secureRandom, 2048);

            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }

        private void SaveKey(string path, object key)
        {
            using (var writer = new StreamWriter(path, false, Encoding.ASCII))
            {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(key);
                pemWriter.Writer.Flush();
            }
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