# AnySharik

Плагин OrcaSlicer для управления 3D-принтерами Anycubic и печати напрямую через **Anycubic Cloud**.

## Возможности

- отдельная вкладка **AnySharik** в стиле Workbench (`Current Print`, `Control`, `About Device`, `Materials`, `Details`, `Firmware info`);
- официальный вход в Anycubic Cloud в отдельном временном окне браузера без сохранения пароля;
- поддержка нескольких принтеров, **ACE Pro** (слоты, цвета, температура, статус сушки) и внешней катушки;
- отправка нарезанного G-code / `.3mf` из **Printer Agent** (`anysharik_cloud`);
- управление печатью (`Pause`, `Resume`, `Stop`), автоопрос Cloud API и TLS MQTT-телеметрия;
- сохранение сессии в `state.json` вне `__whl_extracted__` при обновлении версий.

## Настройка после установки

1. В `File -> Plugins` включите **AnySharik** и capability **`AnySharik printer agent`**, затем перезапустите OrcaSlicer.
2. В настройках OrcaSlicer включите **`Use printer agents instead of print hosts`**.
3. Откройте вкладку **AnySharik**, нажмите **Sign in** и войдите на официальной странице Anycubic Cloud (требуется Microsoft Edge, Google Chrome или совместимый Chromium).
4. В профиле принтера (`Basic information -> Advanced`) выберите **Printer Agent**: **`AnySharik printer agent`** (ID: `anysharik_cloud`) и перезапустите OrcaSlicer.

## Ограничения

- Поддерживаются печать, `Pause`, `Resume`, `Stop` и чтение телеметрии/температур/`ACE Pro`/внешней катушки.
- Видеопоток камеры, ручное перемещение осей и управление нагревом/сушкой ACE Pro через Cloud API пока не поддержаны.

## Безопасность

- Пароль не передаётся плагину; локальный токен хранится в `state.json` внутри каталога данных плагина. Не публикуйте и не передавайте этот файл.
