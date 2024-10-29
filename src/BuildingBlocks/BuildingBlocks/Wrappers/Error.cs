namespace BuildingBlocks.Wrappers;

public sealed record Error(ErrorType ErrorType, string Description)
{
    public static readonly Error None = new(ErrorType.None, string.Empty);
}
