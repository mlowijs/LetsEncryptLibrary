using System.Security.Cryptography;
using LetsEncrypt.Model;

namespace LetsEncrypt;

public interface IKeyStore
{
    Task<KeyStoreEntry?> GetEntryAsync(string accountId);
    Task<KeyStoreEntry?> ImportKeyAsync(Uri accountUrl, ECDsa keyPair);
    Task<byte[]> SignDataAsync(KeyStoreEntry key, byte[] plaintext);
}