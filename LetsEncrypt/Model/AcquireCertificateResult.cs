using System.Security.Cryptography.X509Certificates;

namespace LetsEncrypt.Model;

public record AcquireCertificateResult(bool IsSuccess, X509Certificate2? Certificate = null, AcquireCertificateError? Error = null);

public enum AcquireCertificateError
{
    Unknown = 0,
    
    TimedOut,
    ChallengeInvalid,
    FinalizationFailed
}