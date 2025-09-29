using System.Text.Json.Serialization;

namespace LetsEncrypt.Model;

public record Authorization
{
    [JsonIgnore]
    public Uri Url { get; set; }
    public required string Status { get; init; }
    public required Challenge[] Challenges { get; init; }
    public required Identifier Identifier { get; init; }
    public bool? Wildcard { get; init; }
}