using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;

namespace Sentomaru.AspNetCore;

/// <summary>
/// Helper to extract an RFC 9421 verifiable <see cref="ForwardedMessageDto"/> from an ASP.NET Core <see cref="HttpRequest"/>.
/// </summary>
public static class SentomaruExtractor
{
    /// <summary>Maximum body forwarded for verification (profile limit, 64 KiB).</summary>
    public const int MaxBodyBytes = 65536;

    /// <summary>Client-observed signals header (not signed; forwarded only as a single value).</summary>
    public const string SignalsHeader = "x-sentomaru-signals";

    /// <summary>
    /// The only headers forwarded to Sentomaru: the RFC 9421 covered components of the Sentomaru profile,
    /// Signature/Signature-Input, Content-Type/Content-Length and the client-observed signals header (consumed by
    /// the server policy; it is not signed). The end user's Authorization, Cookie or any other header is never sent.
    /// </summary>
    public static readonly IReadOnlySet<string> ForwardedHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "content-type",
        "content-length",
        "content-digest",
        "x-sentomaru-profile",
        "x-sentomaru-org",
        "x-sentomaru-app",
        "x-sentomaru-environment",
        "x-sentomaru-session",
        "x-sentomaru-operation",
        "signature",
        "signature-input",
        "x-sentomaru-signals",
        "x-sentomaru-operation-id", // 3.1.0 (J-01f): signed business operation id, the same on every retry
        "x-sentomaru-tx-signature" // 4.11.0 (D-25): transaction signature (presence of a person at signing time)
    };

    /// <summary>
    /// Reads and formats the current HTTP request into a ForwardedMessageDto.
    /// Enables stream rewinding on the request body so subsequent middleware/controllers can read it.
    /// </summary>
    public static Task<ForwardedMessageDto> ExtractAsync(
        HttpRequest request,
        string? publicBaseUrlOverride = null,
        CancellationToken cancellationToken = default) =>
        ExtractAsync(request, publicBaseUrlOverride, null, cancellationToken);

    /// <summary>
    /// @target-uri precedence: attribute override, then <see cref="SentomaruClientOptions.PublicBaseUrl"/>, then the
    /// request itself. X-Forwarded-Proto/Host are honoured only when the direct peer is one of
    /// <see cref="SentomaruClientOptions.KnownProxies"/>. 4.7.0: with a public base URL, a path that would replace its
    /// authority (<c>//host/x</c>, <c>/\host/x</c>) throws <see cref="UriFormatException"/>.
    /// </summary>
    public static async Task<ForwardedMessageDto> ExtractAsync(
        HttpRequest request,
        string? publicBaseUrlOverride,
        SentomaruClientOptions? options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // 1. Reconstruct public absolute URI
        var publicBase = !string.IsNullOrWhiteSpace(publicBaseUrlOverride)
            ? publicBaseUrlOverride
            : options?.PublicBaseUrl?.AbsoluteUri;
        string targetUri;
        if (!string.IsNullOrWhiteSpace(publicBase))
        {
            var baseUri = new Uri(publicBase.TrimEnd('/'));
            var pathAndQuery = request.PathBase + request.Path + request.QueryString;
            // 4.7.0 (D-17b review R I-1): a path starting with "//" (or "/\") is a network-path reference: the relative
            // resolution below would take the host from the request instead of publicBaseUrl, and the API does not
            // check the host. Refused (fail closed) as an invalid URI, before anything is read or sent; the resolved
            // authority must also be the configured one.
            if (pathAndQuery.StartsWith("//", StringComparison.Ordinal) || pathAndQuery.StartsWith("/\\", StringComparison.Ordinal))
            {
                throw new UriFormatException("The request path is a network-path reference; @target-uri would leave publicBaseUrl.");
            }
            var resolved = new Uri(baseUri, pathAndQuery);
            if (!string.Equals(resolved.GetLeftPart(UriPartial.Authority), baseUri.GetLeftPart(UriPartial.Authority), StringComparison.Ordinal))
            {
                throw new UriFormatException("The resolved @target-uri does not keep the authority of publicBaseUrl.");
            }
            targetUri = resolved.AbsoluteUri;
        }
        else
        {
            var scheme = request.Scheme;
            var host = request.Host.ToString();
            if (FromKnownProxy(request, options))
            {
                if (request.Headers.TryGetValue("X-Forwarded-Proto", out var proto) && proto == "https")
                {
                    scheme = "https";
                }
                if (request.Headers.TryGetValue("X-Forwarded-Host", out var fwdHost) && !string.IsNullOrWhiteSpace(fwdHost))
                {
                    host = fwdHost.ToString();
                }
            }
            targetUri = $"{scheme}://{host}{request.PathBase}{request.Path}{request.QueryString}";
        }

        // 2. Read and Base64 encode the body (also when Content-Length is absent, e.g. chunked), capped at 64 KiB.
        string base64Body = "";
        if (request.Body is not null && request.ContentLength is not 0)
        {
            if (request.ContentLength > MaxBodyBytes)
            {
                throw new SentomaruBodyTooLargeException();
            }
            request.EnableBuffering();
            request.Body.Position = 0;
            using var memoryStream = new MemoryStream();
            var buffer = new byte[8192];
            int read;
            while ((read = await request.Body.ReadAsync(buffer, cancellationToken)) > 0)
            {
                memoryStream.Write(buffer, 0, read);
                if (memoryStream.Length > MaxBodyBytes)
                {
                    request.Body.Position = 0;
                    throw new SentomaruBodyTooLargeException();
                }
            }
            request.Body.Position = 0;
            base64Body = Convert.ToBase64String(memoryStream.ToArray());
        }

        // 3. Forward only the allowlisted headers
        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in request.Headers)
        {
            if (!ForwardedHeaders.Contains(header.Key)) continue;
            // Final review Minor 3: client-observed signals are forwarded only as one value; several values are dropped
            // (treated as absent = unknown, so sensitive operations get a challenge) instead of failing the whole message.
            if (string.Equals(header.Key, SignalsHeader, StringComparison.OrdinalIgnoreCase) && header.Value.Count != 1) continue;
            headers[header.Key] = header.Value.ToArray()!;
        }

        return new ForwardedMessageDto
        {
            Method = request.Method.ToUpperInvariant(),
            Uri = targetUri,
            Headers = headers,
            Body = base64Body
        };
    }

    private static bool FromKnownProxy(HttpRequest request, SentomaruClientOptions? options)
    {
        var peer = request.HttpContext.Connection.RemoteIpAddress;
        if (peer is null || options is null || options.KnownProxies.Count == 0)
        {
            return false;
        }
        if (peer.IsIPv4MappedToIPv6)
        {
            peer = peer.MapToIPv4();
        }
        return options.KnownProxies.Any(p => System.Net.IPAddress.TryParse(p, out var ip) && ip.Equals(peer));
    }
}

/// <summary>The request body exceeds <see cref="SentomaruExtractor.MaxBodyBytes"/>; it is not forwarded.</summary>
public sealed class SentomaruBodyTooLargeException() : Exception("body-limit");
