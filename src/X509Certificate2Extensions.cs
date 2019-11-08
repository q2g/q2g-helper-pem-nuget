namespace Q2g.HelperPem
{
    #region Usings
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Org.BouncyCastle.Crypto.Parameters;
    using System.Text;
    #endregion

    public static class X509Certificate2Extensions
    {
        #region Public Methods
        public static void SavePem(this X509Certificate2 @this, out string cert, out   string privateKey)
        {
            cert = string.Empty;
            privateKey = string.Empty;
            try
            {
                if (@this.HasPrivateKey)
                {
                    var p = @this.GetRSAPrivateKey().ExportParameters(true);
                    var key = new RsaPrivateCrtKeyParameters(
                        new Org.BouncyCastle.Math.BigInteger(1, p.Modulus), new Org.BouncyCastle.Math.BigInteger(1, p.Exponent), new Org.BouncyCastle.Math.BigInteger(1, p.D),
                        new Org.BouncyCastle.Math.BigInteger(1, p.P), new Org.BouncyCastle.Math.BigInteger(1, p.Q), new Org.BouncyCastle.Math.BigInteger(1, p.DP), new Org.BouncyCastle.Math.BigInteger(1, p.DQ),
                        new Org.BouncyCastle.Math.BigInteger(1, p.InverseQ));
                    using (var stringWriter = new StringWriter())
                    {
                        var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(stringWriter);
                        pemWriter.WriteObject(key);
                        privateKey = stringWriter.GetStringBuilder().ToString();
                    }
                }
                cert = PemCertificateHelper.ExportCertificateToPEM(@this);
            }
            catch (Exception ex)
            {
                throw new Exception($"Certificate could not be saved.  ", ex);
            }
        }

        public static void SavePem(this X509Certificate2 @this, string certFile, string privateKeyFile = null)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(certFile));
                if (!string.IsNullOrEmpty(privateKeyFile) && @this.HasPrivateKey)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(privateKeyFile));
                    var p = @this.GetRSAPrivateKey().ExportParameters(true);
                    var key = new RsaPrivateCrtKeyParameters(
                        new Org.BouncyCastle.Math.BigInteger(1, p.Modulus), new Org.BouncyCastle.Math.BigInteger(1, p.Exponent), new Org.BouncyCastle.Math.BigInteger(1, p.D),
                        new Org.BouncyCastle.Math.BigInteger(1, p.P), new Org.BouncyCastle.Math.BigInteger(1, p.Q), new Org.BouncyCastle.Math.BigInteger(1, p.DP), new Org.BouncyCastle.Math.BigInteger(1, p.DQ),
                        new Org.BouncyCastle.Math.BigInteger(1, p.InverseQ));
                    using (var sw = new StreamWriter(privateKeyFile))
                    {
                        var pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(sw);
                        pemWriter.WriteObject(key);
                    }
                }
                File.WriteAllText(certFile, PemCertificateHelper.ExportCertificateToPEM(@this));
            }
            catch (Exception ex)
            {
                throw new Exception($"Certificate could not be saved. cert: {certFile} - key: {privateKeyFile}", ex);
            }
        }

        public static X509Certificate2 LoadPem(this X509Certificate2 @this, string certFile, string privateKeyFile = null)
        {
            try
            {
                return PemCertificateHelper.ReadPemCertificateWithPrivateKey(certFile, privateKeyFile);
            }
            catch (Exception ex)
            {
                throw new Exception($"Pem certificate {certFile} could not be loaded", ex);
            }
        }
        public static X509Certificate2 LoadPem(this X509Certificate2 @this, byte[] certBuffer, byte[] privateKeyBuffer = null)
        {
            try
            {
                return PemCertificateHelper.ReadPemCertificateWithPrivateKey(certBuffer, privateKeyBuffer);
            }
            catch (Exception ex)
            {
                throw new Exception($"Pem certificate buffer could not be loaded", ex);
            }
        }

        public static X509Certificate2 GenerateQlikJWTConformCert(this X509Certificate2 @this, string subjectName, string issuerName, int keyStrength = 2048)
        {
            try
            {
                return PemCertificateHelper.GenerateSelfSignedCertificate(subjectName, issuerName, keyStrength);
            }
            catch (Exception ex)
            {
                throw new Exception("Certificate could not be generated.", ex);
            }
        }

        public static string GenerateQlikJWToken(this X509Certificate2 @this, List<Claim> Claims, TimeSpan timeValid)
        {
            try
            {
                return GenerateQlikJWToken(@this, Claims, DateTime.Now + timeValid);
            }
            catch (Exception ex)
            {
                throw new Exception("Token with timespan could not be generate.", ex);
            }
        }

        public static string GenerateQlikJWToken(this X509Certificate2 @this, List<Claim> Claims, DateTime untilValid)
        {
            try
            {
                return JwtToken.GenerateToken(@this, Claims, untilValid);
            }
            catch (Exception ex)
            {
                throw new Exception("Token with datetime could not be generated.", ex);
            }
        }

        public static bool ValidateQlikJWToken(this X509Certificate2 @this, string token)
        {
            try
            {
                return JwtToken.ValidateToken(token);
            }
            catch (Exception ex)
            {
                throw new Exception("Token could not be validated", ex);
            }
        }

        public static X509Certificate2 GetQlikClientCertificate(this X509Certificate2 @this, string fullpath = null, string password = null)
        {
            if (String.IsNullOrEmpty(fullpath))
                fullpath = QlikClientCertificate.DefaultFolder;

            if (String.IsNullOrEmpty(password))
                password = Guid.NewGuid().ToString();

            X509Certificate2 cert = null;
            if (fullpath.ToLowerInvariant().EndsWith(".pfx") && File.Exists(fullpath))
            {
                cert = new X509Certificate2(fullpath, password);
            }
            else if (fullpath.ToLowerInvariant().EndsWith(".pem") && File.Exists(fullpath))
            {
                if (String.IsNullOrEmpty(password))
                    password = Guid.NewGuid().ToString();

                var certificate = new QlikClientCertificate(fullpath, password);
                cert = certificate.GetCertificateFromPEM();
            }
            else
            {
                var clientCertPath = Path.Combine(fullpath, "client.pem");
                var clientKeyPath = Path.Combine(fullpath, "client_key.pem");
                var certificate = new QlikClientCertificate(clientCertPath, clientKeyPath, password);
                cert = certificate.GetCertificateFromPEM();
            }

            return cert;
        }
#endregion
    }
}