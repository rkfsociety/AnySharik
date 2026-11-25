# AnySharik Cloud

Плагин для **OrcaSlicer**, добавляющий управление 3D-принтерами Anycubic и печать напрямую через **Anycubic Cloud** без локального LAN-подключения.

## Возможности

- **Вкладка `AnySharik Cloud` в стиле Workbench:**
  - список облачных принтеров аккаунта со статусом `Online` / `Offline`;
  - управление активной печатью (`Pause`, `Resume`, `Stop`) с прогрессом и именем задания;
  - мониторинг температур сопла и стола, автоопрос статуса каждые 5 секунд и TLS MQTT-телеметрия;
  - поддержка **ACE Pro** (статус подключения, прошивка, 4 слота с цветами и типом пластика, текущая температура и статус/остаток времени сушки) и внешней катушки (`external_shelves`), если ACE Pro не подключена;
  - карточка **About Device** с каруселью (`Printer` / `ACE Pro`), копированием `CN` и окнами **Details** (статистика печати, MAC, дата привязки) и **Firmware info**.
- **Printer Agent (`anysharik_cloud`):** отправка нарезанного G-code и `.3mf` напрямую в Anycubic Cloud из кнопки печати OrcaSlicer.
- **Безопасный вход:** официальная авторизация Anycubic Cloud в отдельном временном окне браузера (пароль не запрашивается и не сохраняется). Сессия хранится локально в `state.json` за пределами кэша `__whl_extracted__` и сохраняется при обновлении версий плагина.

## Установка из каталога плагинов OrcaSlicer

> Требуется сборка OrcaSlicer с поддержкой Python Plugins, Pages и Printer Agents (при отсутствии меню `File -> Plugins` используйте актуальную Nightly / compatible сборку).

1. Откройте `File -> Plugins -> Browse plugins`.
2. Найдите **AnySharik Cloud** и установите плагин.
3. В списке плагинов включите пакет **AnySharik Cloud**.
4. Раскройте пакет и включите capability **`AnySharik Cloud printer agent`**.
5. Перезапустите OrcaSlicer.

При первом запуске подтвердите запрошенные плагином разрешения (доступ к `cloud-universe.anycubic.com`, `amazonaws.com`, `mqtt-universe.anycubic.com`, локальному порту входа `19223`, запуску Edge/Chrome для входа и чтению/записи каталога плагина).

## Подключение аккаунта и настройка принтера

1. Откройте вкладку **AnySharik Cloud** и нажмите **Sign in**.
2. Завершите вход в открывшемся официальном окне Anycubic Cloud (включая CAPTCHA / 2FA, если требуется). Для входа нужен Microsoft Edge, Google Chrome или совместимый Chromium.
3. Выберите принтер из списка в левой панели.
4. Откройте профиль принтера в OrcaSlicer: `Basic information -> Advanced`.
5. В поле **Printer Agent** / **Сетевой агент** выберите **`AnySharik Cloud printer agent`** (ID: `anysharik_cloud`).
6. В общих настройках OrcaSlicer включите **`Use printer agents instead of print hosts`** и перезапустите OrcaSlicer.

## Текущие ограничения Cloud API

- В облачном API сейчас поддерживаются загрузка и запуск печати, `Pause`, `Resume`, `Stop`, а также чтение телеметрии, температур, `ACE Pro` и внешней катушки.
- Потоковое видео камеры, ручное перемещение осей (`Axis Control`), запуск/остановка сушки `ACE Pro` и запись целевых температур/вентиляторов из интерфейса пока недоступны через Cloud API.

## Ручная сборка

- Сборка wheel-пакета:

```powershell
py -3 -m pip wheel .\anysharik_cloud --no-deps --wheel-dir .\anysharik_cloud\dist
```

- Установка собранного `.whl` вручную: `File -> Plugins -> Install local plugin`.

## Безопасность

- Пароль от Anycubic Cloud вводится только на официальной странице Anycubic и не передаётся плагину.
- Токен сессии хранится локально в `state.json` в каталоге плагина (`orca_plugins/anysharik_cloud/state.json`). Не публикуйте и не передавайте этот файл.
