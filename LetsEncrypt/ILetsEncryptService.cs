using System.Security.Cryptography;
using LetsEncrypt.Model;

namespace LetsEncrypt;

public interface ILetsEncryptService
{
    Task<bool> CreateAccountAsync(IEnumerable<string> contactEmailAddresses);
    Task<InitializeResult> InitializeAsync(string accountId);
    Task<CreateOrderResult> CreateOrderAsync(string challengeType, IEnumerable<string> hostNames);
    Task<AcquireCertificateResult> AcquireCertificateAsync(Order order, string challengeType, RSA certificateKeyPair, TimeSpan timeout);
}