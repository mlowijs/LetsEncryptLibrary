using System.Buffers.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using LetsEncrypt.Model;

namespace LetsEncrypt.Implementation;

public class LetsEncryptService(LetsEncryptClient client, IKeyStore keyStore) : ILetsEncryptService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(3); 
    
    private KeyStoreEntry? _keyStoreEntry;
    
    public async Task<bool> CreateAccountAsync(IEnumerable<string> contactEmailAddresses)
    {
        var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var account = await client.CreateAccountAsync(contactEmailAddresses, keyPair);
        if (account is null)
            return false;
        
        await keyStore.ImportKeyAsync(account.Url, keyPair);
        return true;
    }

    public async Task<InitializeResult> InitializeAsync(string accountId)
    {
        _keyStoreEntry = await keyStore.GetEntryAsync(accountId);
        if (_keyStoreEntry is null)
            return new(false, InitializeError.KeyNotFound);
        
        client.ConfigureAuthorization(_keyStoreEntry.AccountUrl, plaintext => keyStore.SignDataAsync(_keyStoreEntry, plaintext));
        return new(true);
    }

    public async Task<CreateOrderResult> CreateOrderAsync(string challengeType, IEnumerable<string> hostNames)
    {
        if (_keyStoreEntry is null)
            throw new InvalidOperationException("Service not initialized");
        
        var order = await client.CreateOrderAsync(hostNames);
        if (order is null)
            return new(CreateOrderError.OrderNotFound);

        var authorizations = await Task.WhenAll(order.AuthorizationUrls.Select(client.GetAuthorizationAsync));
        var challenges = new List<ChallengeDetails>();
        
        foreach (var authorization in authorizations)
        {
            var challenge = authorization.Challenges.Single(c => c.Type == challengeType);
            var validationValue = GetValidationValue(challenge);
            
            challenges.Add(new()
            {
                Identifier = authorization.Identifier,
                Challenge = challenge,
                ValidationValue = validationValue
            });
        }

        return new(order, challenges.ToArray());
    }

    public async Task<AcquireCertificateResult> AcquireCertificateAsync(Order order, string challengeType, RSA certificateKeyPair, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        
        var validationResult = await ValidateChallengesAsync(order, challengeType, deadline);
        if (!validationResult.IsSuccess)
            return validationResult;

        if (!await FinalizeOrderAsync(order, certificateKeyPair))
            return new AcquireCertificateResult(false, Error: AcquireCertificateError.FinalizationFailed);

        while (DateTimeOffset.UtcNow < deadline)
        {
            order = await client.GetOrderAsync(order.Url);

            if (order?.Status == Statuses.Valid)
            {
                var certificatePem = await client.DownloadCertificateAsync(order.CertificateUrl!);
                var certificate = X509Certificate2.CreateFromPem(certificatePem);
                return new(true, Certificate: certificate);
            }
            
            await Task.Delay(PollInterval);
        }

        return new AcquireCertificateResult(false, Error: AcquireCertificateError.TimedOut);
    }
    
    private async Task<AcquireCertificateResult> ValidateChallengesAsync(Order order, string challengeType, DateTimeOffset deadline)
    {
        if (_keyStoreEntry is null)
            throw new InvalidOperationException("Service not initialized");

        var authorizations = await Task.WhenAll(order.AuthorizationUrls.Select(client.GetAuthorizationAsync));
        var challenges = authorizations.SelectMany(a => a.Challenges.Where(c => c.Type == challengeType));
        
        await Task.WhenAll(challenges.Select(c => client.ValidateChallengeAsync(c.Url)));
        
        while (DateTimeOffset.UtcNow < deadline)
        {
            authorizations =
                await Task.WhenAll(order.AuthorizationUrls.Select(client.GetAuthorizationAsync));

            if (authorizations.Any(a => a.Status == Statuses.Invalid))
                return new AcquireCertificateResult(false, Error: AcquireCertificateError.ChallengeInvalid);
            
            if (authorizations.All(a => a.Status == Statuses.Valid))
                return new AcquireCertificateResult(true);
            
            await Task.Delay(PollInterval);
        }

        return new AcquireCertificateResult(false, Error: AcquireCertificateError.TimedOut);
    }

    private async Task<bool> FinalizeOrderAsync(Order order, RSA keyPair)
    {
        if (_keyStoreEntry is null)
            throw new InvalidOperationException("Service not initialized");
        
        var dnBuilder = new X500DistinguishedNameBuilder();
        dnBuilder.AddCommonName(order.Identifiers[0].Value);
        
        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var identifier in order.Identifiers.Skip(1))
            sanBuilder.AddDnsName(identifier.Value);
        
        var csr = new CertificateRequest(dnBuilder.Build(), keyPair, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        csr.CertificateExtensions.Add(sanBuilder.Build());

        return await client.FinalizeOrderAsync(order.FinalizeUrl, csr);
    }
    
    private string GetValidationValue(Challenge challenge)
    {
        if (_keyStoreEntry is null)
            throw new InvalidOperationException("Service not initialized");
        
        var keyAuthorization = $"{challenge.Token}.{Base64Url.EncodeToString(_keyStoreEntry.Thumbprint)}";
    
        return challenge.Type switch
        {
            ChallengeTypes.Http01 => keyAuthorization,
            ChallengeTypes.Dns01 => Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(keyAuthorization))),
    
            _ => ""
        };
    }
}