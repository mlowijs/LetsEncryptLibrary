using System.Text.Json.Serialization;

namespace LetsEncrypt.Model;

public record Account
{
    [JsonIgnore]
    public Uri Url { get; set; }
    public required string Status { get; init; }
    [JsonPropertyName("orders")]
    public required Uri OrdersUrl { get; init; }
    [JsonPropertyName("contact")]
    public string[]? Contacts { get; init; }
}