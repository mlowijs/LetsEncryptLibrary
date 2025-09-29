using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using LetsEncrypt.Model;

namespace LetsEncrypt.Implementation;

public class InMemoryKeyStore : IKeyStore
{
    private readonly Dictionary<string, KeyStoreEntry> _entries = new();
    private readonly Dictionary<string, ECDsa> _keyPairs = new();

    public Task<KeyStoreEntry?> GetEntryAsync(string accountId)
    {
        if (!_entries.TryGetValue(accountId, out var entry))
            return Task.FromResult<KeyStoreEntry?>(null);

        return Task.FromResult<KeyStoreEntry?>(entry);
    }

    public Task<KeyStoreEntry?> ImportKeyAsync(Uri accountUrl, ECDsa keyPair)
    {
        var accountId = accountUrl.Segments[^1];
        var entry = new KeyStoreEntry(Guid.CreateVersion7().ToString(), accountUrl, GetThumbprint(keyPair));

        _entries[accountId] = entry;
        _keyPairs[entry.Id] = keyPair;

        return Task.FromResult<KeyStoreEntry?>(entry);
    }

    public async Task<byte[]> SignDataAsync(KeyStoreEntry entry, byte[] plaintext)
    {
        if (!_keyPairs.TryGetValue(entry.Id, out var keyPair))
            return [];

        return keyPair.SignData(plaintext, HashAlgorithmName.SHA256);
    }
    
    private static byte[] GetThumbprint(ECDsa keyPair)
    {
        var ecParams = keyPair.ExportParameters(false);
        
        var jwkBytes = JsonSerializer.SerializeToUtf8Bytes(new EcJwk
        {
            X = Base64Url.EncodeToString(ecParams.Q.X),
            Y = Base64Url.EncodeToString(ecParams.Q.X),
        });
        var thumbprint = SHA256.HashData(jwkBytes);

        return thumbprint;
    }
}