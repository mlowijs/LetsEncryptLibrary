namespace LetsEncrypt.Model;

internal record Jose
{
    public required string Protected { get; init; }
    public required string Payload { get; init; }
    public required string Signature { get; init; }
}