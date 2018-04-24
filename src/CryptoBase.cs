namespace Q2g.HelperPem
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

    public class CryptoBase
    {
        public RsaPrivateCrtKeyParameters PrivateKey { get; private set; }
        public RsaKeyParameters PublicKey { get; private set; }
        public bool HasPrivateKey { get; private set; }

        private AsymmetricCipherKeyPair GetKeyPair()
        {
            var randomGenerator = new VmpcRandomGenerator();
            var secureRandom = new SecureRandom(randomGenerator);
            var keyGenerationParameters = new KeyGenerationParameters(secureRandom, 2048);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }

        protected RSACryptoServiceProvider GetRsaProvider()
        {
            var rsaParameters = new RSAParameters();
            if (HasPrivateKey)
                rsaParameters = PemUtils.ToRSAParameters(PrivateKey);
            else
                rsaParameters = PemUtils.ToRSAParameters(PublicKey);
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);
            return rsa;
        }

        protected void GenerateKeys()
        {
            var pair = GetKeyPair();
            PrivateKey = pair.Private as RsaPrivateCrtKeyParameters;
            PublicKey = pair.Public as RsaKeyParameters;
        }

        protected void ReadKey(string keyPath)
        {
            ReadKey(new FileStream(keyPath, FileMode.Open));
        }

        protected void ReadKey(Stream keyStream)
        {
            using (var reader = new StreamReader(keyStream, Encoding.ASCII))
            {
                var pemReader = new PemReader(reader);
                var pemObject = pemReader.ReadObject();
                if (pemObject is RsaKeyParameters)
                {
                    PublicKey = pemObject as RsaKeyParameters;
                }
                else if (pemObject is AsymmetricCipherKeyPair)
                {
                    var pair = pemObject as AsymmetricCipherKeyPair;
                    PrivateKey = pair.Private as RsaPrivateCrtKeyParameters;
                    PublicKey = pair.Public as RsaKeyParameters;
                    HasPrivateKey = true;
                }
                else
                    throw new Exception($"The key object {pemObject.GetType()} is unkown.");
            }
        }

        protected void SaveKey(string path, object key)
        {
            using (var writer = new StreamWriter(path, false, Encoding.ASCII))
            {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(key);
                pemWriter.Writer.Flush();
            }
        }
    }
}