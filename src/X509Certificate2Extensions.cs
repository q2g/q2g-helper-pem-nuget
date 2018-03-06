#region License
/*
Copyright (c) 2018 Konrad Mattheis und Martin Berthold
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#endregion

namespace Q2gHelperPemNuget
{
    #region Usings
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    #endregion

    public static class X509Certificate2Extensions
    {
        #region Public Methods
        public static void SavePem(this X509Certificate2 @this, string fullname, bool savePrivateKey = false)
        {
            try
            {
                var folder = Path.GetDirectoryName(fullname);
                var name = Path.GetFileNameWithoutExtension(fullname);
                var userKeyPair = PemCertificateHelper.userKeyPair;
                if (savePrivateKey && userKeyPair != null)
                    File.WriteAllText(Path.Combine(folder, $"{name}_private.key"),
                                      $"{PemCertificateHelper.ExportKeyToPEM(userKeyPair.Private)}" +
                                      $"\r\n{PemCertificateHelper.ExportKeyToPEM(userKeyPair.Public)}");

                File.WriteAllText(Path.Combine(folder, $"{name}.pem"), PemCertificateHelper.ExportCertificateToPEM(@this));
            }
            catch (Exception ex)
            {
                throw new Exception("Certificate could not be saved.", ex);
            }
        }

        public static X509Certificate2 LoadPem(this X509Certificate2 @this, string fullname, string privateKeyFile = null)
        {
            try
            {
                return PemCertificateHelper.ReadPemCertificateWithPrivateKey(fullname, privateKeyFile);
            }
            catch (Exception ex)
            {
                throw new Exception($"Pem certificate {fullname} could not be load", ex);
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
                throw new Exception("Certificate could not be generate.", ex);
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
                throw new Exception("Token with datetime could not be generate.", ex);
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
                throw new Exception("Token could not validate", ex);
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