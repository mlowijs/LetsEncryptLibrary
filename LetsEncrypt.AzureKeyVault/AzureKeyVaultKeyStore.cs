using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using LetsEncrypt.Model;

namespace LetsEncrypt.AzureKeyVault;

public class AzureKeyVaultKeyStore(Uri keyVaultUrl, TokenCredential credential) : IKeyStore
{
    private const string KeyNameFormatString = "letsencrypt-account-{0}";
    private const string KeyIdTagName = "kid";
    
    private readonly KeyClient _keyClient = new(keyVaultUrl, credential);

    public async Task<KeyStoreEntry?> GetEntryAsync(string accountId)
    {
        var response = await _keyClient.GetKeyAsync(string.Format(KeyNameFormatString, accountId));
        if (!response.HasValue)
            return null;

        return new(response.Value.Id.AbsoluteUri, new Uri(response.Value.Properties.Tags[KeyIdTagName]), GetThumbprint(response.Value));
    }

    public async Task<KeyStoreEntry?> ImportKeyAsync(Uri accountUrl, ECDsa keyPair)
    {
        var accountId = accountUrl.Segments[^1];
        
        var response = await _keyClient.ImportKeyAsync(
            new(string.Format(KeyNameFormatString, accountId), new JsonWebKey(keyPair, true))
            {
                Properties =
                {
                    Tags =
                    {
                        [KeyIdTagName] = accountUrl.AbsoluteUri
                    }
                }
            });

        if (!response.HasValue)
            return null;
        
        return new(response.Value.Id.AbsoluteUri, accountUrl, GetThumbprint(response.Value));
    }

    public async Task<byte[]> SignDataAsync(KeyStoreEntry key, byte[] plaintext)
    {
        var cryptoClient = new CryptographyClient(new Uri(key.Id), credential);
        var result = await cryptoClient.SignDataAsync(SignatureAlgorithm.ES256, plaintext);

        return result.Signature;
    }

    private static byte[] GetThumbprint(KeyVaultKey key)
    {
        var jwkBytes = JsonSerializer.SerializeToUtf8Bytes(new EcJwk
        {
            X = Base64Url.EncodeToString(key.Key.X),
            Y = Base64Url.EncodeToString(key.Key.Y),
        });
        var thumbprint = SHA256.HashData(jwkBytes);

        return thumbprint;
    }
}