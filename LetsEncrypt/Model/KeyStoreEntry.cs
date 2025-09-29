namespace LetsEncrypt.Model;

public record KeyStoreEntry(string Id, Uri AccountUrl, byte[] Thumbprint);