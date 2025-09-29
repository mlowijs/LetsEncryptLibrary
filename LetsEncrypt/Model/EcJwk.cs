using System.Text.Json.Serialization;

namespace LetsEncrypt.Model;

public record EcJwk
{
    [JsonPropertyName("crv")]
    public string Curve => "P-256";
    [JsonPropertyName("kty")]
    public string KeyType => "EC";
    [JsonPropertyName("x")]
    public required string X { get; init; }
    [JsonPropertyName("y")]
    public required string Y { get; init; }
}