using System.Net.Http.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Talent.ApiClient;

public interface IClientCredentialsTokenProvider
{
    Task<string> GetAccessTokenAsync(CancellationToken ct = default);
}

internal sealed class ClientCredentialsTokenProvider : IClientCredentialsTokenProvider
{
    private const string CacheKey = "talent_cc_token";
    private readonly HttpClient _http;
    private readonly IMemoryCache _cache;
    private readonly TalentAuthOptions _auth;

    public ClientCredentialsTokenProvider(
        HttpClient http,
        IMemoryCache cache,
        IOptions<TalentAuthOptions> authOptions)
    {
        _http = http;
        _cache = cache;
        _auth = authOptions.Value;
    }

    public async Task<string> GetAccessTokenAsync(CancellationToken ct = default)
    {
        if (_cache.TryGetValue<string>(CacheKey, out var token) && !string.IsNullOrWhiteSpace(token))
            return token;

        using var content = new FormUrlEncodedContent(new Dictionary<string, string?>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = _auth.ClientId,
            ["client_secret"] = _auth.ClientSecret,
            ["scope"] = _auth.Scope
        }!);

        var tokenUrl = $"{_auth.Authority.TrimEnd('/')}/connect/token";
        using var resp = await _http.PostAsync(tokenUrl, content, ct);
        var payload = await resp.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: ct);

        if (!resp.IsSuccessStatusCode || payload?.access_token is null)
        {
            var raw = await resp.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Token request failed ({(int)resp.StatusCode}): {raw}");
        }

        // Cache slightly less than expires_in
        var ttl = TimeSpan.FromSeconds(Math.Max(30, payload.expires_in - 30));
        _cache.Set(CacheKey, payload.access_token, ttl);

        return payload.access_token;
    }

    private sealed record TokenResponse(string access_token, int expires_in, string token_type);
}