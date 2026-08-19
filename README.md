<div align="center">

# ssh-mcp-server

[![CI](https://github.com/perhamm/ssh-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/perhamm/ssh-mcp-server/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40perhamm%2Fssh-mcp-server?label=%40perhamm%2Fssh-mcp-server)](https://www.npmjs.com/package/@perhamm/ssh-mcp-server)

MCP-сервер поверх SSH: агент выполняет команды на удалённых машинах, а ключи, пароли и sudo остаются на нашей стороне.

Форк [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server) под ISC.

Русский | [English](README_EN.md) | [中文](README_ZH.md)

</div>

## Что это

ssh-mcp-server это мост между MCP-клиентом (Claude Code, Cursor, Cline) и SSH. Агент вызывает инструменты, сервер подключается к машине и возвращает вывод. Модель не видит ни приватного ключа, ни пароля, ни пароля sudo: всё это читается из локального конфига и переменных окружения процесса.

Один сервер обслуживает любое число хостов. Хост выбирается на лету по алиасу из `~/.ssh/config`, поэтому в конфиг MCP-клиента не нужно вписывать каждую машину.

## Что добавлено в этом форке

| Возможность | Зачем |
|---|---|
| Хосты из `~/.ssh/config` на лету | Один MCP на весь парк. Алиас передаётся в `connectionName`, соединение поднимается при первом обращении |
| ProxyJump | Хост за бастионом доступен по алиасу, цепочка `ProxyJump` разбирается из SSH-конфига |
| sudo из переменной окружения | Агент просит `sudo: true`, пароль подставляет сервер и вырезает его из вывода |
| Запретное ядро | Список операций, которые не выполняются никогда: ни под sudo, ни в любом профиле, ни через SFTP |
| Профили гвардов | Готовый набор запретов `safe` и белый список `readonly`, версионированный и обновляемый |
| Туннели | SOCKS5 (аналог `ssh -D`) и проброс порта (аналог `ssh -L`) на произвольный локальный порт |
| Проверка хост-ключей | `known_hosts` сверяется по умолчанию, ключ не из списка означает отказ подключаться |
| Современная криптография | Ed25519 первым в списке, без SHA-1, CBC и DSA |
| Аудит-лог | Каждый вызов пишется в JSONL с ротацией и gzip-архивами |
| Без загрузки файлов | `upload` по умолчанию не публикуется: файл, который гварды не прочитают, это способ занести код на хост |

## Инструменты

| Инструмент | Что делает |
|---|---|
| `execute-command` | Выполняет команду, умеет `sudo` и произвольный `connectionName` |
| `download` | Забирает файл с сервера |
| `list-servers` | Показывает настроенные соединения, их статус и активный профиль гвардов |
| `list-ssh-hosts` | Показывает алиасы из SSH-конфига, доступные как `connectionName` |
| `open-tunnel` | Поднимает SOCKS5-прокси или проброс порта через соединение |
| `close-tunnel` | Закрывает туннель |
| `list-tunnels` | Показывает открытые туннели и счётчики соединений |

`list-ssh-hosts` появляется только с флагом `--ssh-config-hosts`, туннельные инструменты убираются флагом `--disable-tunnels`. Инструмента `upload` в списке нет: он публикуется только с флагом `--enable-upload`.

## Быстрый старт: один сервер на весь парк

Конфиг MCP-клиента:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--ssh-config-hosts",
        "--guards-profile", "safe"
      ],
      "env": {
        "SSH_MCP_SUDO_PASSWORD": "..."
      }
    }
  }
}
```

Дальше агент работает так:

1. Вызывает `list-ssh-hosts` и находит нужный алиас, например `r-ulybka-prod-master`. У больших конфигов список режется, поэтому агент передаёт `filter`: подстроку или шаблон вида `r-ulybka-*`.
2. Вызывает `execute-command` с `connectionName: "r-ulybka-prod-master"`.
3. Сервер читает алиас из `~/.ssh/config`, берёт оттуда `HostName`, `User`, `Port`, `IdentityFile` и `ProxyJump`, поднимает соединение и выполняет команду.

Ключ при этом не покидает машину: сервер читает файл сам, в диалог попадает только путь из SSH-конфига. Если `IdentityFile` не указан, берётся ssh-agent из `SSH_AUTH_SOCK`. Алиас без `HostName` подключается по собственному имени, как это делает `ssh`.

Достижим только тот алиас, который объявлен в конфиге отдельным блоком `Host`. Блок `Host *` даёт умолчания, но не превращает произвольное имя в достижимый хост.

Список алиасов можно сузить:

```json
"args": [
  "-y", "@perhamm/ssh-mcp-server",
  "--ssh-config-hosts",
  "--allowed-hosts", "r-ulybka-*,*-stage-*",
  "--ssh-config-file", "/home/user/.ssh/config_work"
]
```

Шаблоны поддерживают `*` и `?`. Если алиас не подходит ни под один шаблон, соединение не поднимается, а агент получает ошибку `SSH_HOST_NOT_ALLOWED`.

## Безопасный режим и гварды

Гварды это версионированный набор правил, который проверяет каждую команду до отправки на сервер. Правила лежат в [`guards/default-guards.json`](guards/default-guards.json) и обновляются вместе с репозиторием.

### Профили

| Профиль | Поведение |
|---|---|
| `off` | Правила профиля выключены, работает только запретное ядро. Значение по умолчанию |
| `safe` | Плюс запрет разрушительных команд, остальное разрешает |
| `readonly` | Разрешает только чтение и диагностику, наследует все запреты `safe` |

```json
"args": ["-y", "@perhamm/ssh-mcp-server", "--ssh-config-hosts", "--guards-profile", "safe"]
```

Что ловит `safe` сверх ядра: `shutdown` и `reboot`, сброс firewall, остановку sshd и kubelet, `kubectl delete`, `helm uninstall`, `docker system prune`, удаление пакетов, `DROP DATABASE`, `curl | sh`, `git push --force`, чистку логов, выгрузку модулей ядра, интерактивные редакторы. Полный список с причинами в JSON.

`readonly` дополнительно требует, чтобы каждая часть команды попадала в белый список: `ls`, `cat`, `grep`, `find`, `ps`, `ss`, `df`, `journalctl`, `systemctl status`, `kubectl get/describe/logs`, `docker ps/logs` и подобное. sudo в этом профиле запрещён целиком, вместе с `su`, `doas` и `pkexec`.

### Запретное ядро

Часть операций не выполняется никогда: ни в профиле `off`, ни под sudo, ни через свой файл гвардов, ни через SFTP в обход команд. Список живёт в блоке `forbidden`.

| Категория | Что закрыто |
|---|---|
| Учётные записи | `useradd`, `usermod`, `userdel`, `groupadd`, `passwd`, `chpasswd`, `chage`, `vipw` и запись в `/etc/passwd`, `/etc/shadow`, `/etc/group` |
| sudo | Запись в `/etc/sudoers` и `/etc/sudoers.d`, `visudo` |
| Расписания | `crontab` кроме `crontab -l`, запись в `/etc/cron*`, `/var/spool/cron`, `/etc/anacrontab`, команды `at` и `batch` |
| systemd | Запись юнитов и таймеров в `/etc/systemd`, `/lib/systemd`, `/usr/lib/systemd`, `systemctl edit`, `systemd-run` |
| SSH | Правка `/etc/ssh/*`, `~/.ssh/*`, `authorized_keys`, `sshd_config`, а также `ssh-keygen`, `ssh-copy-id`, `ssh-add` |
| Интерпретаторы | `python`, `perl`, `ruby`, `node`, `php`, `lua`, `Rscript` и запуск скрипта файлом: `bash /tmp/x.sh`, `sh -s`, `source`. Гварды не читают чужой код, поэтому такой запуск закрыт целиком |
| Массовое удаление | `rm -r` каталога первого уровня или системного подкаталога, `rm -r` по маске, `find -delete`, удаление через `xargs rm`, флаг `--no-preserve-root` |
| Диски и секреты | `mkfs`, `wipefs`, `dd of=/dev/`, запись в `/dev/sd*`, форк-бомба, чтение `/etc/shadow` и приватных ключей |

Обычная работа при этом остаётся: `crontab -l`, `cat /etc/ssh/sshd_config`, `systemctl restart nginx`, `rm -rf /var/lib/myapp/cache/tmp` проходят. Разбираемый `bash -c "..."` тоже работает: его содержимое проверяется теми же правилами.

Ядро закрывает и файловые инструменты. `download` не заберёт `/etc/shadow` и содержимое `~/.ssh`, и `allowedRemotePaths` тут ничего не разрешает обратно. Локальная сторона тоже под защитой: `download` не положит файл в наш собственный `~/.ssh`.

Загрузка файлов выключена совсем. Инструмент `upload` не публикуется, пока не передан `--enable-upload`, а профиль `readonly` отклоняет загрузку и с этим флагом.

Если сервер нужен именно для заведения пользователей или правки крона, ядро придётся править в форке осознанно: флага, который его снимает, нет.

### Почему это не обходится точкой с запятой

Команда разбирается на части по `;`, `|`, `&&`, `||`, `&`, переводу строки и подстановкам `$(...)`, и каждая часть проверяется отдельно. Кавычки при разборе учитываются. Так `ls; rm -rf /` не проходит ни в одном профиле, хотя целиком строка начинается с разрешённого `ls`.

Обёртки снимаются перед проверкой: `sudo`, `env`, `timeout 5`, `nohup` и присваивания вида `LC_ALL=C` не прячут команду от правил. Скрипт внутри `bash -c "..."` разбирается отдельно и проверяется теми же правилами. Длина команды ограничена 5000 символами.

Гварды закрывают ошибки агента, а не намеренный обход. Интерпретатор с произвольным кодом внутри, вроде `python -c`, правила не разберут. Там, где обход недопустим, ограничиваем права самого пользователя SSH.

### Обновление правил

Три способа держать правила свежими:

1. Мержим апстрим в свой форк. Файл правил версионирован полем `version`, версия видна в `list-servers` и в тексте отказа.
2. Держим свой файл и указываем его через `--guards-file /etc/ssh-mcp/guards.json`. Правила из него добавляются к встроенным, версия становится `2026.08.19+local-1`.
3. Обновляем файл по расписанию:

```sh
node scripts/update-guards.js https://example.com/guards.json /etc/ssh-mcp/guards.json
```

Скрипт проверяет JSON и компилирует каждое регулярное выражение и только потом заменяет файл. Битая загрузка не ломает работающий набор правил.

Формат своего файла:

```json
{
  "version": "local-1",
  "profiles": {
    "safe": {
      "deny": [
        { "id": "no-ansible", "pattern": "^ansible-playbook\\b", "reason": "выкат идёт из CI" }
      ]
    }
  }
}
```

Поле `scope: "command"` заставляет правило проверять команду целиком, а не по частям. Так работают правила про `curl | sh` и SQL. В блок `forbidden` своего файла можно дописать свои запреты, но встроенные из него не убрать: списки складываются.

Старые `--whitelist` и `--blacklist` никуда не делись и проверяются до гвардов.

## sudo без пароля в диалоге

Пароль sudo лежит в переменной окружения процесса сервера. Агент передаёт `sudo: true`, но самого пароля не видит ни в аргументах вызова, ни в выводе.

```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": ["-y", "@perhamm/ssh-mcp-server", "--ssh-config-hosts", "--guards-profile", "safe"],
      "env": {
        "SSH_MCP_SUDO_PASSWORD": "..."
      }
    }
  }
}
```

Вызов инструмента:

```json
{
  "tool": "execute-command",
  "params": {
    "cmdString": "systemctl restart nginx",
    "connectionName": "r-ulybka-prod-master",
    "sudo": true
  }
}
```

Команда уходит на сервер как `sudo -S -k -p '' -u root -- /bin/sh -c '<команда>'`, пароль пишется в stdin канала. В командной строке его нет, поэтому он не попадает в `ps` и в историю. Псевдотерминал для таких команд отключается, иначе tty отразил бы ввод обратно в вывод. На всякий случай пароль вырезается из вывода и из текста ошибок.

Имя переменной и целевого пользователя меняются флагами `--sudo-password-env` и `--sudo-user`. Если переменная пустая, вызов падает с `SUDO_PASSWORD_MISSING` ещё до подключения. Профиль `readonly` запрещает sudo вообще.

В режиме `shell` пароль дописывается отдельной строкой сразу за командой, так как sudo читает тот же stdin, что и сам shell. Флаг `-k` гарантирует, что запрос пароля будет всегда и строка не выполнится как команда. Для sudo лучше режим `exec`.

## Туннели

`open-tunnel` поднимает локальный слушатель и гонит трафик через SSH-соединение. Полезно, когда до сервисов кластера нет прямого доступа, а до узла есть.

SOCKS5 на порту 8777:

```json
{
  "tool": "open-tunnel",
  "params": {
    "type": "socks5",
    "localPort": 8777,
    "connectionName": "r-ulybka-prod-master"
  }
}
```

Дальше любой клиент ходит через прокси, имена резолвятся на удалённой стороне:

```sh
curl --socks5-hostname 127.0.0.1:8777 http://prometheus.monitoring.svc:9090/api/v1/query?query=up
kubectl --request-timeout=30s ... # через HTTPS_PROXY=socks5h://127.0.0.1:8777
```

Проброс одного порта, аналог `ssh -L`:

```json
{
  "tool": "open-tunnel",
  "params": {
    "type": "local",
    "localPort": 15432,
    "remoteHost": "pg-master.internal",
    "remotePort": 5432
  }
}
```

Если `localPort` не указан, порт выбирает система и возвращает его в ответе. Туннели живут до `close-tunnel`, до обрыва SSH-соединения или до остановки сервера.

Ограничения задаются флагами:

| Флаг | Значение по умолчанию | Что делает |
|---|---|---|
| `--tunnel-bind-address` | `127.0.0.1` | Адрес, на котором слушают туннели |
| `--allowed-tunnel-ports` | нет ограничений | Список портов, которые разрешено занимать |
| `--max-tunnels` | 8 | Сколько туннелей держим одновременно |
| `--disable-tunnels` | выключено | Убирает туннельные инструменты из списка |

Слушатель по умолчанию поднимается на loopback. Адрес шире loopback открывает прокси в вашу сеть, поэтому меняем его осознанно.

## Проверка хост-ключей

Ключ сервера сверяется с `known_hosts` при каждом подключении, включая промежуточные хосты цепочки `ProxyJump`. По умолчанию режим `strict`: хоста нет в `known_hosts` означает отказ.

| Режим | Поведение |
|---|---|
| `strict` | По умолчанию. Подключаемся только к хостам из `known_hosts` |
| `accept-new` | Незнакомый хост записывается при первом подключении, расхождение ключа по-прежнему отказ |
| `off` | Проверки нет, поведение апстрима |

Проверяются `~/.ssh/known_hosts`, `~/.ssh/known_hosts2` и `/etc/ssh/ssh_known_hosts`, а для алиаса с `UserKnownHostsFile` тот файл, который указан в SSH-конфиге. Свой список задаётся флагом `--known-hosts-file`. Понимаются хешированные записи, шаблоны, форма `[host]:port` и метка `@revoked`.

Отказ приходит кодом `SSH_HOST_KEY_REJECTED` и текстом с отпечатком:

```text
Host key of prod.example.com is not in known_hosts (~/.ssh/known_hosts): ssh-ed25519 SHA256:xxxx.
Verify that fingerprint, add the host to known_hosts, or start the server with --host-key-checking accept-new.
```

Расхождение ключа не принимается никогда и ни в каком режиме: сервер отказывается подключаться и пишет, что хост либо пересоздан, либо кто-то встал посередине.

Для первого знакомства с парком удобно один раз пройти с `--host-key-checking accept-new`, а дальше вернуть `strict`.

## Аудит-лог

Каждый вызов пишется строкой JSON: команда, соединение, флаг sudo, вердикт гварда, длительность, объём вывода. Содержимое вывода в лог не попадает, пароль sudo вырезается.

```json
{"time":"2026-08-19T08:12:44.101Z","pid":8123,"event":"command","result":"blocked","connection":"r-ulybka-prod-master","command":"useradd deploy","sudo":true,"code":"COMMAND_VALIDATION_FAILED","reason":"Blocked by the forbidden core ..."}
{"time":"2026-08-19T08:12:51.880Z","pid":8123,"event":"command","result":"ok","connection":"r-ulybka-prod-master","command":"systemctl status nginx","sudo":false,"durationMs":412,"bytes":1840}
```

Пишутся события `connect`, `command`, `download`, `upload`, `tunnel-open`, `tunnel-close`, `host-key`.

По умолчанию файл лежит в `$XDG_STATE_HOME/ssh-mcp-server/audit.jsonl`, то есть обычно `~/.local/state/ssh-mcp-server/audit.jsonl`, права `0600`.

| Флаг | По умолчанию | Что делает |
|---|---|---|
| `--audit-log <path>` | каталог состояния XDG | Путь к логу, значение `off` выключает запись |
| `--audit-max-size <bytes>` | 10485760 | Размер, после которого файл ротируется. `0` отключает встроенную ротацию |
| `--audit-keep <count>` | 10 | Сколько gzip-архивов держим |

Ротация встроенная: по достижении лимита текущий файл переезжает в `audit.jsonl.1.gz`, старые архивы сдвигаются, всё за пределами `--audit-keep` удаляется. Десять архивов по 10 МиБ это порядка сотни мегабайт в несжатом виде и заметно меньше после gzip.

Если логами уже управляет logrotate, ставим `--audit-max-size 0` и настраиваем ротацию режимом `copytruncate`.

Ошибка записи не роняет команду: сервер один раз пишет об этом в stderr и продолжает работать.

## Способы подключения

Ниже сценарии от простого к сложному. В `args` каждый флаг и его значение это два отдельных элемента массива: `"--host", "192.168.1.1"`, а не `"--host 192.168.1.1"`.

### Логин и пароль

```json
{
  "mcpServers": {
    "ssh-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@perhamm/ssh-mcp-server",
        "--host", "192.168.1.1",
        "--port", "22",
        "--username", "root",
        "--password", "pwd123456"
      ]
    }
  }
}
```

### Приватный ключ

```json
"args": [
  "-y", "@perhamm/ssh-mcp-server",
  "--host", "192.168.1.1",
  "--username", "root",
  "--privateKey", "~/.ssh/id_rsa",
  "--passphrase", "pwd123456"
]
```

Пароль от ключа можно не писать в конфиг, а положить в переменную `SSH_MCP_PASSPHRASE`.

### Один алиас из `~/.ssh/config`

```json
"args": ["-y", "@perhamm/ssh-mcp-server", "--host", "myserver"]
```

Сервер читает `HostName`, `Port`, `User`, `IdentityFile` и `ProxyJump` из блока `Host myserver`, включая директивы `Include` и шаблоны. Флаги командной строки приоритетнее: `--port 2222` перебивает порт из конфига.

### Бастион и ProxyJump

Если у алиаса есть `ProxyJump`, цепочка поднимается сама:

```
Host r-ulybka-prod-master
    HostName 10.20.30.40
    User ops
    ProxyJump bastion
    IdentityFile ~/.ssh/prod_key
```

Каждый следующий хоп подключается через канал предыдущего, как это делает `ssh -J`. Цепочку можно задать и вручную: `--proxy-jump "bastion,gateway:2222"`. Глубина цепочки ограничена пятью хопами.

### Прокси

```json
"args": [
  "-y", "@perhamm/ssh-mcp-server",
  "--host", "192.168.1.1",
  "--username", "root",
  "--password", "pwd123456",
  "--proxy", "socks5://user:pwd@proxy-host:1080"
]
```

Поддерживаются `socks://`, `socks5://`, `http://` и `https://`. HTTP и HTTPS ходят методом `CONNECT` с Basic-аутентификацией, порт по умолчанию 80 и 443. Для SOCKS5 порт обязателен. Старый флаг `--socksProxy` работает, но принимает только SOCKS. Вместе `--proxy` и `--proxy-jump` не используются.

### Джамп-хост с интерактивным shell

`transportMode` по умолчанию `exec`. Переключаемся на `shell`, если после успешного логина команды не выполняются или железка отдаёт только интерактивную сессию:

```json
"args": [
  "-y", "@perhamm/ssh-mcp-server",
  "--host", "bastion.example.com",
  "--username", "ops",
  "--password", "pwd123456",
  "--transport-mode", "shell",
  "--shell-ready-timeout", "15000"
]
```

В режиме `shell` команды идут по очереди через одну постоянную сессию, а `upload` и `download` не работают: SFTP там отключён.

### Двухфакторная аутентификация

Флаг `--try-keyboard` включает keyboard-interactive. Пароль и ключ подставляются сами, код из второго фактора читается из переменной `SSH_MCP_2FA_CODE`.

### Несколько соединений в одном сервере

Кроме алиасов из SSH-конфига остаётся старый способ: файл с описанием соединений.

```json
[
  {
    "name": "dev",
    "host": "1.2.3.4",
    "port": 22,
    "username": "alice",
    "privateKey": "~/.ssh/dev_key",
    "guardProfile": "safe",
    "commandTimeoutMs": 120000
  },
  {
    "name": "prod",
    "host": "5.6.7.8",
    "port": 22,
    "username": "bob",
    "privateKey": "~/.ssh/prod_key",
    "guardProfile": "readonly",
    "allowedRemotePaths": ["/var/log", "/tmp"]
  }
]
```

```json
"args": ["-y", "@perhamm/ssh-mcp-server", "--config-file", "/abs/path/ssh-config.json"]
```

Формат объекта, где ключ это имя соединения, тоже поддерживается. Соединение выбирается параметром `connectionName`, без него берётся первое.

## Ограничения команд и путей

### Белый и чёрный списки

```json
"args": [
  "-y", "@perhamm/ssh-mcp-server",
  "--host", "192.168.1.1",
  "--username", "root",
  "--privateKey", "~/.ssh/id_rsa",
  "--whitelist", "^ls( .*)?,^cat .*,^df.*",
  "--blacklist", "^rm .*,^shutdown.*"
]
```

Шаблоны это регулярные выражения через запятую. Команда сначала проверяется по белому списку, потом по чёрному, потом по профилю гвардов, и должна пройти все три проверки.

### Шаблон команды

`--command-template` оборачивает каждую команду. `<quotedCommand>` подставляет команду как экранированный аргумент, `<command>` вставляет её как есть. Шаблон применяется после подстановки рабочего каталога.

```
su root -c <quotedCommand>
docker exec -i mycontainer sh -c <quotedCommand>
```

### Пути для файловых операций

`--allowed-local-paths` расширяет список локальных каталогов, доступных для `upload` и `download` (по умолчанию только текущий каталог). `--allowed-remote-paths` ограничивает удалённые пути, туда пишем абсолютные POSIX-пути через запятую. Без этого флага SFTP видит всю файловую систему хоста, о чём сервер предупреждает при старте.

## Таймауты и лимит вывода

| Параметр | По умолчанию | Что ограничивает |
|---|---|---|
| `timeout` в вызове инструмента | нет | Одну команду, перебивает настройки соединения |
| `commandTimeoutMs` | 30000 | Команду в режиме `exec` |
| `shellCommandTimeoutMs` | 30000 | Команду в режиме `shell` |
| `connectionTimeoutMs` | 30000 | Установку соединения и хендшейк |
| `sftpTimeoutMs` | 300000 | Операции SFTP |
| `maxOutputBytes` | 10485760 | Захваченный вывод одной команды |
| `keepaliveIntervalMs` | 10000 | Интервал keepalive |

При превышении лимита вывода команда обрывается, а инструмент возвращает `OUTPUT_LIMIT_EXCEEDED` вместе с уже собранным куском. Ошибки приходят структурой из `code`, `message` и `retriable`.

## Флаги командной строки

```text
  --config-file <path>             Файл с описанием соединений
  --ssh-config-file <path>         Путь к SSH-конфигу (по умолчанию ~/.ssh/config)
  --ssh <config>                   Соединение как JSON или пары key=value
  -h, --host <host>                Хост или алиас из SSH-конфига
  -p, --port <port>                Порт
  -u, --username <name>            Пользователь
  -w, --password <password>        Пароль
  -k, --privateKey <path>          Путь к приватному ключу
  -P, --passphrase <passphrase>    Пароль от ключа
  -a, --agent <path>               Сокет ssh-agent
  -W, --whitelist <patterns>       Белый список команд, через запятую
  -B, --blacklist <patterns>       Чёрный список команд, через запятую
  --proxy <url>                    Прокси SOCKS5, HTTP или HTTPS
  -s, --socksProxy <url>           Старый флаг только для SOCKS5
  --allowed-local-paths <paths>    Локальные каталоги для upload и download
  --allowed-remote-paths <paths>   Удалённые каталоги для SFTP
  --transport-mode <mode>          exec или shell (по умолчанию exec)
  --shell-ready-timeout <ms>       Таймаут готовности shell (по умолчанию 10000)
  --command-template <template>    Шаблон с <command> или <quotedCommand>
  --pty                            Псевдотерминал для exec (по умолчанию включён)
  --try-keyboard                   Keyboard-interactive для 2FA
  --pre-connect                    Подключиться ко всем хостам при старте
  --ssh-config-hosts               Разрешить хосты из SSH-конфига на лету
  --allowed-hosts <patterns>       Шаблоны разрешённых алиасов, через запятую
  --proxy-jump <chain>             Цепочка ProxyJump, через запятую
  --guards-profile <name>          off, safe или readonly (по умолчанию off)
  --guards-file <path>             Свой набор правил поверх встроенного
  --sudo-password-env <var>        Переменная с паролем sudo
  --sudo-user <user>               Пользователь для sudo (по умолчанию root)
  --host-key-checking <mode>       strict, accept-new или off (по умолчанию strict)
  --known-hosts-file <paths>       Свои файлы known_hosts, через запятую
  --host-key-algorithms <list>     Алгоритмы хост-ключа, через запятую
  --enable-upload                  Опубликовать инструмент upload (по умолчанию выключен)
  --audit-log <path|off>           Путь к аудит-логу (по умолчанию каталог состояния XDG)
  --audit-max-size <bytes>         Порог ротации, 0 отключает (по умолчанию 10485760)
  --audit-keep <count>             Сколько архивов держим (по умолчанию 10)
  --disable-tunnels                Убрать туннельные инструменты
  --tunnel-bind-address <addr>     Адрес для туннелей (по умолчанию 127.0.0.1)
  --allowed-tunnel-ports <ports>   Разрешённые порты туннелей, через запятую
  --max-tunnels <count>            Лимит одновременных туннелей (по умолчанию 8)
  --version, -v                    Версия пакета
  --help                           Справка
```

## Безопасность

- Для прода включаем `--guards-profile safe`, для дежурного разбора инцидентов подходит `readonly`. С `off` остаётся только запретное ядро: всё остальное выполнится, о чём сервер и пишет предупреждение в лог.
- Ключ, его пароль и пароль sudo читаются из файлов и переменных окружения. В конфиге MCP-клиента храним путь к ключу, а не сам ключ.
- Туннели слушают loopback. У SOCKS5 нет аутентификации, поэтому прокси на `0.0.0.0` открывает внутреннюю сеть всем, кто дотянется до порта, и сервер пишет об этом предупреждение при старте.
- Без `--allowed-remote-paths` через SFTP читается и пишется любой путь на хосте, включая `~/.ssh/authorized_keys`.
- Ключ хоста сверяется с `known_hosts` в режиме `strict`. Снимать проверку через `--host-key-checking off` стоит только в лаборатории.
- Ограничений частоты вызовов нет.

## Разработка

```sh
npm install
npm run build
npm test
```

Тесты запускаются встроенным раннером Node.js и лежат в [`test/`](test/).

## Апстрим и лицензия

Проект вырос из [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server) (автор junki.cn), лицензия ISC. Копирайт апстрима сохранён в [LICENSE](LICENSE), там же ссылка на исходный репозиторий.

Набор гвардов частично собран по идеям [tufantunc/ssh-mcp](https://github.com/tufantunc/ssh-mcp) (MIT).

Пакет в NPM: [@perhamm/ssh-mcp-server](https://www.npmjs.com/package/@perhamm/ssh-mcp-server).
