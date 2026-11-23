# kauliki_network_scanner

Автономный агент проверки VPN и MTProxy для Windows, Linux и macOS. Можно запускать
на VPS, рабочем ПК или ноутбуке, работающем лишь часть дня. Python **3.11+**.

Агент получает готовые задания через HTTPS, проверяет настоящий протокол и отправляет
результаты пакетами. Ему нужны только адрес API и **его собственный API_KEY**, выданный
администратором. PostgreSQL, SSH, Telegram, harvest-источников и данных других сканеров
в этом проекте нет. Проверяемые VPN/MTProxy передаются только в выданных заданиях.

## Быстрый запуск

После клонирования этого репозитория создайте окружение и установите пакет.

Linux/macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m kauliki_network_scanner configure
.venv/bin/python -m kauliki_network_scanner install-core
.venv/bin/python -m kauliki_network_scanner run
```

Windows, PowerShell:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m kauliki_network_scanner configure
.\.venv\Scripts\python.exe -m kauliki_network_scanner install-core
.\.venv\Scripts\python.exe -m kauliki_network_scanner run
```

Можно использовать установленный Python 3.11/3.12/3.13 вместо 3.14. `configure`
запрашивает индивидуальный ключ без отображения и создаёт `scanner.yaml` и приватный
`credentials.json`. По умолчанию API — `https://api.kauliki.ru`; другой origin:

```bash
python -m kauliki_network_scanner configure --api-url https://api.example.org
```

Права администратора для самого сканирования и TUN не нужны. Агент не подключает
системный VPN: отдельные ядра слушают только loopback и используются для проб.
sing-box устанавливается отдельно; архив сверяется с закреплённым SHA256 официального
релиза **1.14.4**. Доступны amd64/arm64 сборки Windows, Linux и macOS. Для MTProxy
ядро не требуется; при отсутствии sing-box MTProxy продолжает работать.

## Настройки устройства

Пример — [config.example.yaml](config.example.yaml). Файл не содержит списков прокси,
серверных секретов и чужих ключей. Можно указать собственный `API_KEY` прямо в локальном
YAML либо `API_KEY_ENV`, но удобнее оставить отдельный `credentials.json`.

Основные ограничения:

- `vpn_full_workers`, `vpn_health_workers`, `mtproxy_full_workers`,
  `mtproxy_health_workers`: отдельные очереди, ноль отключает направление.
- `core_start_concurrency`: ограничение одновременных холодных запусков.
- `max_pending_results` и `max_storage_mb`: при накоплении очереди новые задания
  приостанавливаются; сохранённые результаты не удаляются из-за сетевой ошибки.
- `pause_on_battery`: пауза выдачи новых работ от батареи.
- `active_hours` и `active_days`: время работы по локальным часам, поддерживается
  интервал через полночь. Без настройки работает, пока запущен процесс.

Обычный ноутбук: 2 full + 2 health VPN и по одному MTProxy worker. Для VPS с ресурсами
можно выставить 6 full + 4 health VPN и по одному MTProxy. Сервер дополнительно
ограничивает количество одновременных заданий для каждого ключа.

```bash
python -m kauliki_network_scanner validate-config
python -m kauliki_network_scanner status
python -m kauliki_network_scanner run --duration 120
```

Отключение по Ctrl+C сохраняет законченные измерения. Задания и outbox находятся в
`state/outbox.sqlite3`. После сбоя завершённые измерения доставляются повторно с теми
же UUID; они не превращаются в дополнительные успехи. Незавершённое после аварии
задание не перезапускается как новый раунд: его аренда освобождается сервером.

HTTPS API проверяет сертификат и не следует перенаправлениям с ключом. HTTP допустим
только для явных loopback-тестов (`allow_http_loopback: true`); для удалённого API
используйте HTTPS. Настройки системных HTTP-прокси окружения не наследуются.
Сканер измеряет фактический сетевой маршрут ОС: работающий сторонний TUN влияет на
локацию измерения. Для проверки своего провайдера используйте соответствующий прямой
маршрут и согласуйте сетевую группу с администратором.

## Автостарт

Сначала выполните обычный запуск и убедитесь, что администратор включил ваш ключ.
Команда создаёт определение автозапуска с абсолютными путями; ключ в него не помещается.

Linux, пользовательский systemd:

```bash
.venv/bin/python -m kauliki_network_scanner autostart --output kauliki-network-scanner.service
mkdir -p ~/.config/systemd/user
cp kauliki-network-scanner.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now kauliki-network-scanner.service
```

Без lingering пользовательская служба запускается при входе пользователя.
Для постоянно работающего VPS используйте стандартный systemd service нужного
пользователя либо настройте lingering штатными средствами администратора.

Windows, запуск при входе текущего пользователя:

```powershell
.\.venv\Scripts\python.exe -m kauliki_network_scanner autostart --output kauliki-network-scanner.xml
Register-ScheduledTask -TaskName KaulikiNetworkScanner -Xml (Get-Content -Raw .\kauliki-network-scanner.xml) -User "$env:USERDOMAIN\$env:USERNAME" -Force
Start-ScheduledTask -TaskName KaulikiNetworkScanner
```

Задача работает без повышения прав и перезапускается при отказе. Один каталог
состояния может принадлежать только одному процессу. У каждого отдельного устройства
должны быть собственный ключ и каталог; не копируйте `credentials.json` между ПК.

macOS, пользовательский launchd:

```bash
.venv/bin/python -m kauliki_network_scanner autostart --output ru.kauliki.network-scanner.plist
mkdir -p ~/Library/LaunchAgents
cp ru.kauliki.network-scanner.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/ru.kauliki.network-scanner.plist
```

## Проверки и обновление

```bash
python -m unittest discover -s tests -v
```

Протокольные тесты используют локальные зашифрованные эмуляторы, реальные TCP/AES/TLS,
подтверждённую передачу и отрицательные проверки UUID/secret/certificate. Публичные
VPN и Telegram-аккаунты для тестов не нужны. Установите core через `config.example.yaml`
или задайте `SINGBOX_TEST_BINARY`; без ядра VPN-интеграции пропускаются.

GitHub Actions проверяет Python 3.11 и 3.14 на Windows, Linux и macOS. API-контракт
имеет версию 1; несовместимые версии не исполняются. Обновление кода — обычный
`git pull` / `pip install -e .` и перезапуск. Сервер не отправляет команды shell,
пути к произвольным исполняемым файлам или обновления для выполнения на ПК.

Не публикуйте локальные `scanner.yaml`, `credentials.json`, `state/` и журналы;
они исключены через `.gitignore`. Код лицензирован MIT; отдельно установленный
sing-box распространяется его разработчиками под своей лицензией GPLv3.
