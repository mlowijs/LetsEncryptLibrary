using System.Text.Json.Serialization;

namespace LetsEncrypt.Model;

public record Order
{
    [JsonIgnore]
    public Uri Url { get; set; }
    public required string Status { get; init; }
    [JsonPropertyName("authorizations")]
    public required Uri[] AuthorizationUrls { get; init; }
    [JsonPropertyName("finalize")]
    public required Uri FinalizeUrl { get; init; }
    public required Identifier[] Identifiers { get; init; }
    [JsonPropertyName("certificate")]
    public Uri? CertificateUrl { get; init; }
}