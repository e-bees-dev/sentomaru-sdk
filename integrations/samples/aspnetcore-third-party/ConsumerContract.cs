using System.Net;
using System.Text;
using System.Text.Json;

namespace ThirdPartyApi;

// guide:begin contract
/// <summary>
/// C-09 (#142): contract checks to copy into the test suite of YOUR backend (any test framework: each returns null when
/// the contract holds, or the reason it does not). The challenge route must take subject/tenant from the authenticated
/// session, never from the body. Needs: an HttpClient to your backend (anonymous for the first check, authenticated
/// as a known user for the second), and, for the second, a way to read what your backend sent to Sentomaru (a fake
/// Sentomaru transport in your tests, as ThirdPartySampleTests does).
/// </summary>
public static class ConsumerContract
{
    private const string Body = """{"subject":"someone-else","tenant":"another-tenant"}""";

    /// <summary>Anonymous call that claims an identity in the body: 401, or 403 with code caller-context-missing.</summary>
    public static async Task<string?> ChallengeRefusesAnonymousCallerAsync(HttpClient anonymous,
        string path = "/integrity/challenges", CancellationToken ct = default)
    {
        using var content = new StringContent(Body, Encoding.UTF8, "application/json");
        using var response = await anonymous.PostAsync(path, content, ct);
        if (response.StatusCode == HttpStatusCode.Unauthorized) return null;
        if (response.StatusCode == HttpStatusCode.Forbidden &&
            await CodeAsync(response, ct) == "caller-context-missing") return null;
        return $"{path} answered {(int)response.StatusCode} to an anonymous caller; expected 401, or 403 caller-context-missing";
    }

    /// <summary>Authenticated call whose body names someone else: the challenge goes out for the SESSION caller.</summary>
    public static async Task<string?> ChallengeUsesTheSessionCallerAsync(HttpClient authenticated,
        Func<(string Subject, string Tenant)?> lastSentToSentomaru, string sessionSubject, string sessionTenant,
        string path = "/integrity/challenges", CancellationToken ct = default)
    {
        using var content = new StringContent(Body, Encoding.UTF8, "application/json");
        using var response = await authenticated.PostAsync(path, content, ct);
        if (!response.IsSuccessStatusCode) return $"{path} answered {(int)response.StatusCode} to an authenticated caller";
        var sent = lastSentToSentomaru();
        return sent == (sessionSubject, sessionTenant)
            ? null
            : $"{path} sent {sent?.Subject}/{sent?.Tenant} to Sentomaru instead of the session caller {sessionSubject}/{sessionTenant}";
    }

    private static async Task<string?> CodeAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            return doc.RootElement.TryGetProperty("code", out var code) ? code.GetString() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
// guide:end contract
