namespace Q2g.HelperPem
{
    #region Usings
    using Org.BouncyCastle.Crypto.Parameters;
    using System.Security.Cryptography;
    #endregion

    internal class PemUtilsHelper
    {
        #region Public Methods
        public static RSA ToRSA(RsaKeyParameters rsaKey)
        {
            var rp = ToRSAParameters(rsaKey);
            var rsaCsp = new RSACryptoServiceProvider();
            rsaCsp.ImportParameters(rp);
            return rsaCsp;
        }

        public static RSA ToRSA(RsaPrivateCrtKeyParameters privKey)
        {
            var rp = ToRSAParameters(privKey);
            var rsaCsp = new RSACryptoServiceProvider();
            rsaCsp.ImportParameters(rp);
            return rsaCsp;
        }

        public static RSAParameters ToRSAParameters(RsaKeyParameters rsaKey)
        {
            var rp = new RSAParameters()
            {
                Modulus = rsaKey.Modulus.ToByteArrayUnsigned(),
            };

            if (rsaKey.IsPrivate)
                rp.D = rsaKey.Exponent.ToByteArrayUnsigned();
            else
                rp.Exponent = rsaKey.Exponent.ToByteArrayUnsigned();
            return rp;
        }

        public static RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privKey)
        {
            var rp = new RSAParameters()
            {
                Modulus = privKey.Modulus.ToByteArrayUnsigned(),
                Exponent = privKey.PublicExponent.ToByteArrayUnsigned(),
                D = privKey.Exponent.ToByteArrayUnsigned(),
                P = privKey.P.ToByteArrayUnsigned(),
                Q = privKey.Q.ToByteArrayUnsigned(),
                DP = privKey.DP.ToByteArrayUnsigned(),
                DQ = privKey.DQ.ToByteArrayUnsigned(),
                InverseQ = privKey.QInv.ToByteArrayUnsigned()
            };
            return rp;
        }
        #endregion
    }
}