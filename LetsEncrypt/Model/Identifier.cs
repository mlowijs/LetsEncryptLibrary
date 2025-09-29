namespace LetsEncrypt.Model;

public record Identifier
{
    public required string Type { get; init; }
    public required string Value { get; init; }
}