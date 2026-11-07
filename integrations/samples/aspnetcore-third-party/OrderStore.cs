namespace ThirdPartyApi;

/// <summary>
/// In-memory stand-in for the consumer's own database. The charge and its receipt by operation id are written
/// together (one lock here; one transaction in a real database), so a receipt exists exactly when the charge does.
/// </summary>
public sealed class OrderStore
{
    private readonly object transaction = new();
    private readonly Dictionary<string, string> receipts = new();
    private int completions;
    private int charges;

    public int Completions => Volatile.Read(ref completions);
    public int Charges => Volatile.Read(ref charges);

    public void Complete(string id) => Interlocked.Increment(ref completions);

    public string Charge(string id, string? operationId)
    {
        lock (transaction)
        {
            var receipt = $"receipt-{id}-{Interlocked.Increment(ref charges)}";
            if (operationId is not null) receipts[operationId] = receipt;
            return receipt;
        }
    }

    public string? ReceiptFor(string operationId)
    {
        lock (transaction) return receipts.TryGetValue(operationId, out var r) ? r : null;
    }
}
