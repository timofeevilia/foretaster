"""Page text in both languages. Plain text only: the builder escapes every value."""

REPOSITORY = "https://github.com/timofeevilia/foretaster"
COMMAND = "uvx --from git+https://github.com/timofeevilia/foretaster foretaster scan"

CONTENT: dict[str, dict[str, str]] = {
    "en": {
        "lang": "en",
        "title": "Foretaster: check the tools connected to an AI assistant",
        "description": "An open-source scanner that checks AI agent configurations and MCP tool "
        "descriptions for hidden commands. The check on this page runs in your browser.",
        "other_lang": "Русский",
        "nav_how": "How the attack works",
        "nav_try": "Try it",
        "nav_measured": "Measurements",
        "hero_eyebrow": "Open-source scanner for AI agents",
        "hero_title": "Foretaster checks the tools connected to an AI assistant for hidden "
        "commands before the assistant reads them",
        "hero_lead": "It reads agent configuration files and the descriptions of connected "
        "tools, and reports poisoned descriptions, exposed keys and risky settings. The check "
        "on this page runs entirely in your browser, so nothing you paste leaves your computer.",
        "hero_try": "Try it on this page",
        "hero_code": "Code on GitHub",
        "how_eyebrow": "How the attack works",
        "how_title": "A tool's description is read by the model, not by a person",
        "how_intro": "Connecting a tool to an assistant looks like installing a plug-in, and it "
        "carries a risk that is easy to miss.",
        "how_1": "A tool is connected to the assistant and gives it access to, for example, "
        "mail, files or a calendar.",
        "how_2": "The tool arrives with a text saying what it can do, and the model reads that "
        "text in full as an instruction.",
        "how_3": "If a command is hidden in the text, such as reading the file with the keys "
        "and not reporting it, the assistant may carry it out.",
        "try_eyebrow": "Try it",
        "try_title": "Paste an agent configuration or a tool list and see what the scanner reports",
        "try_intro": "The field accepts the configuration file of Claude Desktop, Claude Code, "
        "Cursor, VS Code or Windsurf, or a saved list of a server's tools. Two examples with "
        "typical problems are provided.",
        "try_example_config": "Example: risky configuration",
        "try_example_tools": "Example: poisoned tool",
        "try_run": "Check",
        "try_placeholder": "Paste JSON here",
        "try_privacy": "The scanner is downloaded once, about 15 MB, and then runs on your "
        "device. This page is not allowed to connect to any other site, and it stores nothing.",
        "ui_loading": "Loading the scanner, about 15 MB, which is needed only once.",
        "ui_scanning": "Checking.",
        "ui_done": "Done.",
        "ui_failed": "The scanner could not be started:",
        "ui_empty": "The field is empty. Paste a configuration or load an example.",
        "ui_unreadable": "The text could not be read:",
        "ui_scanned": "Checked {servers} server(s) and {tools} tool(s). Findings:",
        "ui_clean": "none.",
        "ui_line": "line",
        "ui_server": "server",
        "ui_tool": "tool",
        "ui_fix": "Fix:",
        "finds_eyebrow": "What it looks for",
        "finds_title": "Nineteen checks in three groups",
        "finds_1_title": "Tool descriptions",
        "finds_1": "Instructions addressed to the model, invisible characters, references to "
        "key files, requests to hide an action from the user, parameters built to carry data "
        "out, and attempts to control the tools of another server.",
        "finds_2_title": "Configuration",
        "finds_2": "Keys and tokens stored in plain text, packages downloaded without a fixed "
        "version, connections without encryption, servers started through a shell script, "
        "look-alike package names and access to the whole disk.",
        "finds_3_title": "Changes and combinations",
        "finds_3": "A description that changed after it was approved, identical tool names on "
        "different servers, and an assistant that can at once read private data, take in "
        "outside content and send data out.",
        "measured_eyebrow": "Measurements",
        "measured_title": "A high result is obtained on attacks whose devices were already known",
        "measured_intro": "The scanner was measured on two public collections of attacks. The "
        "figures differ almost threefold, and both are shown because either one alone would "
        "mislead.",
        "chart_1_title": "First collection",
        "chart_1_text": "Attacks from the collection on which the rules were improved; the "
        "figures are for the part set aside and not looked at.",
        "chart_2_title": "Second collection",
        "chart_2_text": "Attacks by three other authors, never used for tuning.",
        "bar_before": "before tuning",
        "bar_after": "after tuning",
        "bar_devices": "recognisable devices",
        "bar_plain": "plain language",
        "bar_all": "all attacks",
        "of": "of",
        "caveat_1": "Rules based on patterns find attacks whose wording someone has already "
        "seen. Attacks written in ordinary business language mostly pass.",
        "caveat_2": "On the first collection {fp_hits} of {fp_total} genuine tools was flagged "
        "by mistake. In the second, {trap_hits} of {trap_total} harmless tool lists were "
        "flagged; they were written as traps, such as a manager of SSH keys.",
        "caveat_3": "An automatic check supplements caution about what is connected to an "
        "assistant and does not replace it.",
        "measured_link": "Method, limits and full tables",
        "run_eyebrow": "On your own machine",
        "run_title": "One command checks every agent configuration found on the computer",
        "run_intro": "It needs the free uv tool and installs nothing permanently. The scanner "
        "only reads files, it does not start or contact any server unless asked to, and its "
        "reports can be read by GitHub code scanning.",
        "footer_license": "Open source under the Apache-2.0 licence.",
        "footer_code": "Source code",
        "footer_security": "Report a vulnerability",
        "footer_benchmark": "Benchmark",
    },
    "ru": {
        "lang": "ru",
        "title": "Foretaster: проверка инструментов, подключённых к AI-ассистенту",
        "description": "Открытый сканер, который проверяет настройки AI-агентов и описания "
        "MCP-инструментов на скрытые команды. Проверка на этой странице выполняется в браузере.",
        "other_lang": "English",
        "nav_how": "Как устроена атака",
        "nav_try": "Попробовать",
        "nav_measured": "Измерения",
        "hero_eyebrow": "Открытый сканер для AI-агентов",
        "hero_title": "Foretaster проверяет инструменты, подключённые к AI-ассистенту, на "
        "скрытые команды до того, как ассистент их прочитает",
        "hero_lead": "Он читает файлы настроек агентов и описания подключённых инструментов и "
        "сообщает об отравленных описаниях, открыто лежащих ключах и рискованных настройках. "
        "Проверка на этой странице целиком выполняется в браузере, поэтому вставленный текст "
        "не покидает ваш компьютер.",
        "hero_try": "Попробовать на этой странице",
        "hero_code": "Код на GitHub",
        "how_eyebrow": "Как устроена атака",
        "how_title": "Описание инструмента читает модель, а не человек",
        "how_intro": "Подключение инструмента к ассистенту похоже на установку дополнения, и "
        "в нём есть риск, который легко не заметить.",
        "how_1": "К ассистенту подключают инструмент, который даёт ему доступ, например, к "
        "почте, файлам или календарю.",
        "how_2": "Вместе с инструментом приходит текст о том, что он умеет, и модель читает "
        "этот текст целиком как инструкцию.",
        "how_3": "Если в тексте спрятана команда, например прочитать файл с ключами и не "
        "сообщать об этом, ассистент может её выполнить.",
        "try_eyebrow": "Попробовать",
        "try_title": "Вставьте настройки агента или список инструментов и посмотрите, что "
        "сообщит сканер",
        "try_intro": "Поле принимает файл настроек Claude Desktop, Claude Code, Cursor, VS Code "
        "или Windsurf, а также сохранённый список инструментов сервера. Есть два примера с "
        "типичными проблемами.",
        "try_example_config": "Пример: рискованные настройки",
        "try_example_tools": "Пример: отравленный инструмент",
        "try_run": "Проверить",
        "try_placeholder": "Вставьте сюда JSON",
        "try_privacy": "Сканер загружается один раз, около 15 МБ, и дальше работает на вашем "
        "устройстве. Этой странице запрещено соединяться с другими сайтами, и она ничего не "
        "сохраняет. Отчёт сканера выводится на английском языке.",
        "ui_loading": "Загружается сканер, около 15 МБ; это нужно только один раз.",
        "ui_scanning": "Идёт проверка.",
        "ui_done": "Готово.",
        "ui_failed": "Сканер не удалось запустить:",
        "ui_empty": "Поле пустое. Вставьте настройки или загрузите пример.",
        "ui_unreadable": "Текст не удалось прочитать:",
        "ui_scanned": "Проверено серверов: {servers}, инструментов: {tools}. Находки:",
        "ui_clean": "нет.",
        "ui_line": "строка",
        "ui_server": "сервер",
        "ui_tool": "инструмент",
        "ui_fix": "Что делать:",
        "finds_eyebrow": "Что он ищет",
        "finds_title": "Девятнадцать проверок в трёх группах",
        "finds_1_title": "Описания инструментов",
        "finds_1": "Инструкции, адресованные модели, невидимые символы, упоминания файлов с "
        "ключами, просьбы скрыть действие от пользователя, параметры для вывоза данных и "
        "попытки управлять инструментами чужого сервера.",
        "finds_2_title": "Настройки",
        "finds_2": "Ключи и токены открытым текстом, пакеты без закреплённой версии, "
        "соединения без шифрования, запуск сервера через shell-скрипт, имена пакетов, похожие "
        "на известные, и доступ ко всему диску.",
        "finds_3_title": "Изменения и сочетания",
        "finds_3": "Описание, которое изменилось после одобрения, одинаковые имена "
        "инструментов у разных серверов и ассистент, который одновременно читает приватные "
        "данные, принимает чужой контент и может отправлять данные наружу.",
        "measured_eyebrow": "Измерения",
        "measured_title": "Высокий результат получается на атаках, приёмы которых уже были "
        "известны",
        "measured_intro": "Сканер измерялся на двух открытых наборах атак. Результаты "
        "различаются почти втрое, и показаны оба, потому что любой из них по отдельности "
        "вводил бы в заблуждение.",
        "chart_1_title": "Первый набор",
        "chart_1_text": "Атаки из набора, на котором улучшались правила; числа относятся к "
        "отложенной части, на которую при этом не смотрели.",
        "chart_2_title": "Второй набор",
        "chart_2_text": "Атаки трёх других авторов, которые не использовались при настройке.",
        "bar_before": "до настройки",
        "bar_after": "после настройки",
        "bar_devices": "узнаваемые приёмы",
        "bar_plain": "обычный язык",
        "bar_all": "все атаки",
        "of": "из",
        "caveat_1": "Правила на шаблонах находят атаки, формулировки которых кто-то уже "
        "видел. Атаки, написанные обычным деловым языком, в основном проходят мимо.",
        "caveat_2": "В первом наборе по ошибке отмечен {fp_hits} из {fp_total} настоящих "
        "инструментов. Во втором отмечены {trap_hits} из {trap_total} безобидных списков "
        "инструментов; они написаны как ловушки, например менеджер SSH-ключей.",
        "caveat_3": "Автоматическая проверка дополняет осторожность при подключении "
        "инструментов к ассистенту, но не заменяет её.",
        "measured_link": "Методика, ограничения и полные таблицы",
        "run_eyebrow": "На своём компьютере",
        "run_title": "Одна команда проверяет все настройки агентов, найденные на компьютере",
        "run_intro": "Для неё нужна бесплатная программа uv, и она ничего не устанавливает "
        "насовсем. Сканер только читает файлы, не запускает серверы и не обращается к ним без "
        "явного указания, а его отчёты понимает GitHub code scanning.",
        "footer_license": "Открытый код под лицензией Apache-2.0.",
        "footer_code": "Исходный код",
        "footer_security": "Сообщить об уязвимости",
        "footer_benchmark": "Бенчмарк",
    },
}
