namespace LetsEncrypt.Model;

public record InitializeResult(bool IsSuccess, InitializeError? Error = null);

public enum InitializeError
{
    Unknown = 0,
    
    KeyNotFound
}