using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using LetsEncrypt.Model;

namespace LetsEncrypt;

public interface ILetsEncryptClient
{
    Task<Account?> CreateAccountAsync(IEnumerable<string> emailAddresses, ECDsa keyPair);
    void ConfigureAuthorization(Uri accountUrl, Func<byte[], Task<byte[]>> signData);
    Task<Order?> GetOrderAsync(Uri orderUrl);
    Task<Order?> CreateOrderAsync(IEnumerable<string> hostNames);
    Task<Authorization?> GetAuthorizationAsync(Uri authorizationUrl);
    Task<Challenge?> ValidateChallengeAsync(Uri challengeUrl);
    Task<bool> FinalizeOrderAsync(Uri finalizeUrl, CertificateRequest certificateRequest);
    Task<string?> DownloadCertificateAsync(Uri certificateUrl);
}