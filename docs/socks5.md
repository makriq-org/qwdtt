# Расширенный SOCKS5-режим

`qwdtt -mode socks` поднимает локальный SOCKS5 (TCP CONNECT и UDP ASSOCIATE)
поверх userspace-туннеля. Это универсальный режим: им пользуются FlClashM и
любые другие клиенты, отдельного «режима FlClashM» нет.

## Режимы туннеля

| `tunnel` | Транспорт |
|---|---|
| `wireguard` (по умолчанию) | WireGuard поверх DTLS |
| `wireguard-direct` | WireGuard без DTLS (нужен сервер с `-listen-direct`) |
| `raw-ip` | сырые IP-пакеты без WireGuard и DTLS (нужен сервер с `-listen-raw`) |

Все три режима используют один и тот же gVisor netstack, поэтому TCP, UDP,
DNS и QUIC работают одинаково. Legacy-флаги сохранены: `-notls` включает
`wireguard-direct`, `-mode rawtun` — `raw-ip` с Android TUN.

## Конфигурационный файл

Секреты не передаются в argv: FlClashM (и любой другой супервизор) передаёт
только `-config /path/to/config.json`. Файл должен быть недоступен группе и
остальным (`0600`). Явно заданные флаги имеют приоритет над файлом.

```json
{
  "mode": "socks",
  "peer": "vpn.example.com:56003",
  "password": "connection-password",
  "vk-hashes": ["CALL_HASH_1"],
  "workers": 9,
  "tunnel": "raw-ip",
  "obfs": "audio",
  "udp": true,
  "turn-transport": "udp",
  "turn-servers": ["192.0.2.10", "192.0.2.20:443"],
  "turn-port": 3478,
  "dns-server": "system",
  "socks": {
    "listen": "127.0.0.1:36500",
    "username": "flclashm",
    "password": "local-socks-password",
    "auth": true,
    "udp": true,
    "udp-token": true
  },
  "device-id": "node-id",
  "captcha-mode": "native"
}
```

- `turn-servers` и `turn-port` необязательны. Приоритет порта: порт из
  `turn-servers`, затем `turn-port`, затем порт из ответа VK.
- `dns-server`: `system` или `IP[:порт]`. Явный DNS не заменяется DNS
  оператора. `system` использует DNS, выданный сервером (WireGuard/RAWCONF):
  он гарантированно достижим внутри туннеля. `dns-fallback` и
  `/etc/resolv.conf` применяются только как резерв, потому что физический DNS
  телефона находится вне туннеля; они не подменяют серверный резолвер.
- `workers`: от 1 до `27 × число хешей`. Группы по 9 сохраняются, последняя
  может быть неполной. Один воркер — допустимая группа.
- `captcha-mode: native` — только нативная автоматическая обработка капчи,
  без WebView и без участия пользователя. Если VK не пускает, узел штатно
  завершает попытку и переходит в недоступность.
- SOCKS5 слушает только loopback. При `udp-token: true` обязательны
  авторизация SOCKS5 и UDP; токен передаётся как доменное имя в UDP
  ASSOCIATE и как префикс каждой датаграммы (`flclashm-udp-token`).

## Несколько узлов

Каждый процесс qwdtt обслуживает один узел. Несколько узлов запускаются
независимыми процессами с разными `socks.listen`, `device-id` и файлами
конфигурации. WireGuard-loopback по умолчанию занимает свободный порт
(`127.0.0.1:0`), поэтому узлы не конфликтуют.

## Ошибки применения конфигурации

Если конфигурацию туннеля не удалось применить (некорректный `RAWCONF`, DNS,
netstack или WireGuard), процесс пишет причину и завершается с кодом 1.
Супервизор должен перезапустить его. Возврат из обработчика оставил бы занятый
loopback-порт без SOCKS5-сервера: снаружи процесс выглядел бы живым, но трафик
бы не обслуживался.
