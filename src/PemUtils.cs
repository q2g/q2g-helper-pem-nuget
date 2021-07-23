namespace Q2g.HelperPem
{
    #region Usings
    using System;
    using System.Security.Cryptography.X509Certificates;
    #endregion

    public class PemUtils
    {
        #region Public Methods
        public static void AddRootCertifcateToStore(X509Certificate2 certificate)
        {
            // The whole thing works only with administrative rights!!!
            try
            {
                var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                var storeCertificates = store.Certificates.Find(X509FindType.FindByIssuerName, certificate.FriendlyName, false);
                foreach (var storeCert in storeCertificates)
                    store.Remove(storeCert);
                store.Add(certificate);
                store.Close();
            }
            catch (Exception ex)
            {
                throw new Exception("The certificate could not be added to the certificate store.", ex);
            }
        }

        public static void RemoveRootCertifcateFromStore(string friendlyName)
        {
            // The whole thing works only with administrative rights!!!
            try
            {
                var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                var storeCertificates = store.Certificates.Find(X509FindType.FindByIssuerName, friendlyName, false);
                foreach (var storeCert in storeCertificates)
                    store.Remove(storeCert);
                store.Close();
            }
            catch (Exception ex)
            {
                throw new Exception("The certificate could not be removed from the certificate store.", ex);
            }
        }
        #endregion
    }
}