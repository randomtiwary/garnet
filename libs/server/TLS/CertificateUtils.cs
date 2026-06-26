// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Garnet.server.TLS
{
    /// <summary>
    /// CertificateUtils
    /// </summary>
    public static class CertificateUtils
    {
        /// <summary>
        /// Gets machine certificate by subject name
        /// </summary>
        /// <param name="subjectName"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public static X509Certificate2 GetMachineCertificateBySubjectName(string subjectName)
        {
            X509Store store = null;
            X509Certificate2 certificate;

            try
            {
                store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);

                var certificateCollection = store.Certificates
                    .Find(X509FindType.FindBySubjectName, subjectName, false);

                if (certificateCollection.Count <= 0)
                {
                    throw new ArgumentException(
                        $"Unable to load certificate with subject name {subjectName}");
                }

                var latestMatchingCert = certificateCollection.OfType<X509Certificate2>().OrderByDescending(cert => cert.NotAfter).First();
                certificate = new X509Certificate2(latestMatchingCert);
            }
            finally
            {
                store?.Close();
            }

            return certificate;
        }


        /// <summary>
        /// Gets a certificate (and private key) from a file path.
        /// Supports PKCS#12 (.pfx / .p12) and PEM formats (.pem / .crt / .cer, or any file whose
        /// contents begin with a PEM header). For PEM, the private key may live in the same file
        /// as the certificate, or in a separate key file provided via <paramref name="keyFileName"/>.
        /// </summary>
        /// <param name="fileName">Path to the certificate file (PKCS#12 or PEM).</param>
        /// <param name="password">Password for PKCS#12 archives or encrypted PEM private keys; optional for unencrypted PEM.</param>
        /// <param name="keyFileName">Optional path to a PEM private key when it is not embedded in <paramref name="fileName"/>.</param>
        /// <returns>An <see cref="X509Certificate2"/> that includes the private key when present.</returns>
        /// <exception cref="ArgumentException"></exception>
        public static X509Certificate2 GetMachineCertificateByFile(string fileName, string password, string keyFileName = null)
        {
            if (string.IsNullOrEmpty(fileName))
                throw new ArgumentException("Certificate file name must be provided.", nameof(fileName));

            if (IsPemCertificateSource(fileName, keyFileName))
            {
                try
                {
                    if (!string.IsNullOrEmpty(password))
                        return X509Certificate2.CreateFromEncryptedPemFile(fileName, password, keyFileName);

                    return X509Certificate2.CreateFromPemFile(fileName, keyFileName);
                }
                catch (Exception ex)
                {
                    throw new ArgumentException(
                        $"Unable to load PEM certificate from '{fileName}'" +
                        (string.IsNullOrEmpty(keyFileName) ? string.Empty : $" (key: '{keyFileName}')") +
                        $": {ex.Message}",
                        ex);
                }
            }

#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadPkcs12FromFile(fileName, password);
#else
            return new X509Certificate2(fileName, password);
#endif
        }

        /// <summary>
        /// Returns true when the certificate (or an explicitly provided key file) should be loaded as PEM.
        /// PKCS#12 extensions always take precedence so mixed naming is handled predictably.
        /// </summary>
        internal static bool IsPemCertificateSource(string fileName, string keyFileName = null)
        {
            if (HasPkcs12Extension(fileName))
                return false;

            if (HasPemExtension(fileName) || LooksLikePemFile(fileName))
                return true;

            // Separate key file is only meaningful for PEM workflows.
            if (!string.IsNullOrEmpty(keyFileName) &&
                (HasPemExtension(keyFileName) || LooksLikePemFile(keyFileName)))
                return true;

            return false;
        }

        static bool HasPkcs12Extension(string path)
        {
            var ext = Path.GetExtension(path);
            return ext.Equals(".pfx", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".p12", StringComparison.OrdinalIgnoreCase);
        }

        static bool HasPemExtension(string path)
        {
            var ext = Path.GetExtension(path);
            return ext.Equals(".pem", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".crt", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".cer", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".key", StringComparison.OrdinalIgnoreCase);
        }

        static bool LooksLikePemFile(string path)
        {
            try
            {
                // Read a small prefix so we can accept extension-less PEM files.
                using var stream = File.OpenRead(path);
                Span<byte> buffer = stackalloc byte[64];
                int read = stream.Read(buffer);
                if (read <= 0)
                    return false;

                var text = System.Text.Encoding.ASCII.GetString(buffer.Slice(0, read));
                return text.Contains("-----BEGIN", StringComparison.Ordinal);
            }
            catch
            {
                return false;
            }
        }
    }
}
