namespace LetsEncrypt.Model;

public record CreateOrderResult
{
    public CreateOrderResult(Order order, ChallengeDetails[] challenges)
    {
        IsSuccess = true;
        Order = order;
        Challenges = challenges;
    }

    public CreateOrderResult(CreateOrderError error)
    {
        IsSuccess = false;
        Error = error;
    }
    
    public bool IsSuccess { get; init; }
    public Order? Order { get; init; }
    public ChallengeDetails[]? Challenges { get; init; }
    public CreateOrderError? Error { get; init; }
}

public record ChallengeDetails
{
    public required Challenge Challenge { get; init; }
    public required Identifier Identifier { get; init; }
    public required string ValidationValue { get; init; }
}

public enum CreateOrderError
{
    Unknown = 0,
    
    OrderNotFound
}