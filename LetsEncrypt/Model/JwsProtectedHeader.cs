using System.Text.Json.Serialization;

namespace LetsEncrypt.Model;

internal record JwsProtectedHeader
{
    private JwsProtectedHeader(string nonce, Uri url)
    {
        Nonce = nonce;
        Url = url;
    }
    
    public JwsProtectedHeader(string keyId, string nonce, Uri url) : this(nonce, url)
    {
        KeyId = keyId;
    }
    
    public JwsProtectedHeader(EcJwk jwk, string nonce, Uri url) : this(nonce, url)
    {
        JsonWebKey = jwk;
    }
    
    [JsonPropertyName("alg")]
    public string Algorithm { get; } = "ES256";
    [JsonPropertyName("jwk")]
    public EcJwk? JsonWebKey { get; }
    [JsonPropertyName("kid")]
    public string? KeyId { get; }
    public string Nonce { get; }
    public Uri Url { get; }
};