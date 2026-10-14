CSPSIGNER - ПАКЕТНОЕ ПОДПИСАНИЕ ФАЙЛОВ ЧЕРЕЗ КРИПТОПРО CSP

Русская инструкция: README.md
English instructions: README.en.md
Технический справочник / Technical reference: REFERENCE.md
https://github.com/Alox1d/act-signer/releases/latest

Нужны Windows PowerShell 5.1, КриптоПро CSP, локальные CAdESCOM,
Windows Script Host, действующий сертификат ГОСТ-2012 и его ключ.
Для токена нужен драйвер. В VM всё должно быть доступно внутри гостя.

1. Полностью распакуйте CSPSigner-VERSION.zip и откройте Start.cmd.
2. Укажите размещение результата, сертификат и формат имени.
3. Выберите папку (поиск начнётся сразу) или Выбрать файлы...
4. Проверьте список и нажмите Проверить и подписать.
5. PIN вводите в штатном окне КриптоПро или токена.

Ctrl/Shift выделяет строки; пробел меняет галочки группы.
Выбрать все / Снять все меняют весь список. Обновить список сохраняет выбор.
Архивы при поиске папки без галочек; выбранные явно файлы отмечены.

Формат файлов произвольный, размер одного файла - до 64 МиБ.
По умолчанию: report.docx -> report.docx_ivanov.sig.
Исходник не изменяется. Сохраняйте его вместе с SIG.
Подтверждённая подпись выбранным сертификатом пропускается без ключа.
Существующие файлы не перезаписываются. Ошибка отдельного файла
не мешает независимым; отмена криптооперации останавливает пакет.

Настройки: %LOCALAPPDATA%\CSPSigner\settings.json.
Журнал: <папка результата>\_CSPSigner_logs.
Настройки ActSigner переносятся при первом запуске.
Обновление включается при следующем запуске Start.cmd.
Диагностика: diagnostics\Check-CryptoPro.cmd.
Не публикуйте ключи, PIN и рабочие документы.

ENGLISH QUICK START (APPLICATION UI IS IN RUSSIAN)
1. Extract CSPSigner-VERSION.zip and open Start.cmd.
2. Choose output mode, certificate and naming format.
3. Choose a folder to scan it automatically, or select individual files.
4. Review the list and click Проверить и подписать (check and sign).
5. Enter the PIN in the standard CryptoPro or token dialog.
Ctrl/Shift highlights rows; Space toggles their checkboxes.
Folder archives start unchecked; explicitly picked files start checked.

Requires CryptoPro CSP, local CAdESCOM, Windows Script Host,
Windows PowerShell 5.1 and a valid GOST-2012 certificate/private key.
Any content format up to 64 MiB per file. Original bytes stay unchanged.
Keep source and detached SIG together. See README.en.md for details.
