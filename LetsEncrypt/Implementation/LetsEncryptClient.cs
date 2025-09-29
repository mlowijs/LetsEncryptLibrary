using System.Buffers.Text;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LetsEncrypt.Model;

namespace LetsEncrypt.Implementation;

public class LetsEncryptClient(bool staging = false) : ILetsEncryptClient
{
    private static readonly Uri StagingBaseUrl = new("https://acme-staging-v02.api.letsencrypt.org/acme/");
    private static readonly Uri ProductionBaseUrl = new("https://acme-v02.api.letsencrypt.org/acme/");
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient _httpClient = new();
    private readonly Uri _url = staging ? StagingBaseUrl : ProductionBaseUrl;

    private Uri? _accountUrl;
    private Func<byte[], Task<byte[]>>? _signData;
    
    public void ConfigureAuthorization(Uri accountUrl, Func<byte[], Task<byte[]>> signData)
    {
        _accountUrl = accountUrl;
        _signData = signData;
    }
    
    public async Task<Account?> CreateAccountAsync(IEnumerable<string> emailAddresses, ECDsa keyPair)
    {
        var response = await SendAuthenticatedRequest(new Uri(_url, "new-acct"), new
        {
            termsOfServiceAgreed = true,
            contact = emailAddresses.Select(e => $"mailto:{e}").ToArray()
        }, keyPair);

        if (!response.IsSuccessStatusCode)
            return null;

        var account = await response.Content.ReadFromJsonAsync<Account>(SerializerOptions);
        account!.Url = response.Headers.Location!;

        return account;
    }

    public async Task<Order?> GetOrderAsync(Uri orderUrl)
    {
        var response = await SendAuthenticatedRequest(orderUrl, "");
        if (!response.IsSuccessStatusCode)
            return null;

        var responseObject = await response.Content.ReadFromJsonAsync<Order>(SerializerOptions);
        responseObject!.Url = orderUrl;
        
        return responseObject;
    }
    
    public async Task<Order?> CreateOrderAsync(IEnumerable<string> hostNames)
    {
        var response = await SendAuthenticatedRequest(new Uri(_url, "new-order"), new
        {
            identifiers = hostNames.Select(h => new
            {
                type = "dns",
                value = h
            }).ToArray()
        });

        if (!response.IsSuccessStatusCode)
            return null;

        var order = await response.Content.ReadFromJsonAsync<Order>(SerializerOptions);
        order!.Url = response.Headers.Location!;
        
        return order;
    }

    public async Task<Authorization?> GetAuthorizationAsync(Uri authorizationUrl)
    {
        var response = await SendAuthenticatedRequest(authorizationUrl, "");
        if (!response.IsSuccessStatusCode)
            return null;
        
        var authorization = await response.Content.ReadFromJsonAsync<Authorization>(SerializerOptions);
        authorization!.Url = authorizationUrl;

        return authorization;
    }

    public async Task<Challenge?> ValidateChallengeAsync(Uri challengeUrl)
    {
        var response = await SendAuthenticatedRequest(challengeUrl, new {});
        if (!response.IsSuccessStatusCode)
            return null;
        
        return await response.Content.ReadFromJsonAsync<Challenge>(SerializerOptions);
    }

    public async Task<bool> FinalizeOrderAsync(Uri finalizeUrl, CertificateRequest certificateRequest)
    {
        var response = await SendAuthenticatedRequest(finalizeUrl, new
        {
            csr = Base64Url.EncodeToString(certificateRequest.CreateSigningRequest())
        });

        return response.IsSuccessStatusCode;
    }

    public async Task<string?> DownloadCertificateAsync(Uri certificateUrl)
    {
        var response = await SendAuthenticatedRequest(certificateUrl, "");
        if (!response.IsSuccessStatusCode)
            return null;
        
        return await response.Content.ReadAsStringAsync();
    }
    
    private async Task<HttpResponseMessage> SendAuthenticatedRequest(Uri url, object payload, ECDsa? keyPair = null)
    {
        if (_accountUrl is null || _signData is null)
            throw new InvalidOperationException("Authorization not configured.");
        
        var nonceRequest = new HttpRequestMessage(HttpMethod.Head, new Uri(_url, "new-nonce"));
        var nonceResponse = await _httpClient.SendAsync(nonceRequest);
        var nonce = nonceResponse.Headers.GetValues("Replay-Nonce").First();
        
        var protectedHeader = new JwsProtectedHeader(_accountUrl.AbsoluteUri, nonce, url);
        if (keyPair is not null)
        {
            var ecParams = keyPair.ExportParameters(false);
            protectedHeader = new JwsProtectedHeader(new EcJwk
            {
                X = Base64Url.EncodeToString(ecParams.Q.X),
                Y = Base64Url.EncodeToString(ecParams.Q.Y),
            }, nonce, url);
        }
        
        var joseProtected =
            Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(protectedHeader, SerializerOptions));
        var josePayload = payload as string 
                          ?? Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(payload));

        var bytesToSign = Encoding.UTF8.GetBytes($"{joseProtected}.{josePayload}");
        var signature = keyPair is not null
            ? keyPair.SignData(bytesToSign, HashAlgorithmName.SHA256)
            : await _signData(bytesToSign);

        var jose = new Jose
        {
            Protected = joseProtected,
            Payload = josePayload,
            Signature = Base64Url.EncodeToString(signature)
        };
        
        var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new StringContent(JsonSerializer.Serialize(jose, SerializerOptions));
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json", null);
        var response = await _httpClient.SendAsync(request);

        return response;
    }
}