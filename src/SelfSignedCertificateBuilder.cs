namespace Q2g.HelperPem
{
    #region Usings
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    #endregion

    public class SelfSignedCertificateBuilder
    {
        #region Properties
        public SubjectAlternativeNameBuilder SubjectAlternativeNames { get; private set; } = new SubjectAlternativeNameBuilder();
        public string CertifcateName { get; private set; }
        public string Password { get; private set; }
        #endregion

        #region Constructor
        public SelfSignedCertificateBuilder(string certificateName, string password)
        {
            CertifcateName = certificateName;
            Password = password;
        }
        #endregion

        #region Public Methods
        public byte[] Generate()
        {
            try
            {
                var distinguishedName = new X500DistinguishedName($"CN={CertifcateName}");
                using RSA rsa = RSA.Create(4096);
                var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment |
                                                  X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
                request.CertificateExtensions.Add(SubjectAlternativeNames.Build());
                var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));
                certificate.FriendlyName = CertifcateName;
                return certificate.Export(X509ContentType.Pfx, Password);
            }
            catch (Exception ex)
            {
                throw new Exception("The certificate could not build.", ex);
            }
        }
        #endregion
    }
}