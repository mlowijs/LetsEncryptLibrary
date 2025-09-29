
namespace LetsEncrypt.Model;

public record Challenge
{
    public required Uri Url { get; init; }
    public required string Type { get; init; }
    public required string Status { get; init; }
    public required string Token { get; init; }
}