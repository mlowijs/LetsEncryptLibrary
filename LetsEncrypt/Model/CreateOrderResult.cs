namespace LetsEncrypt.Model;

public record CreateOrderResult
{
    public required Order Order { get; init; }
    public required ChallengeDetails[] Challenges { get; init; }
}

public record ChallengeDetails
{
    public required Challenge Challenge { get; init; }
    public required Identifier Identifier { get; init; }
    public required string ValidationValue { get; init; }
}