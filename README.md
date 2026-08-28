# 🛡️ Автономный семейный VPN-пайплайн (0 ₽)

Полностью автономный, бесплатный пайплайн для автосбора, тестирования задержки и раздачи VLESS/Shadowsocks/Trojan подписок для семьи на базе **GitHub Actions** и **GitHub Pages**.

---

## 🌟 Возможности и Архитектура

- **2 независимых пула в единой подписке**:
  1. **`⚡ Обход Белых Списков` (Emergency Whitelist)**:
     - Жесткая фильтрация узлов по SNI/Host из белого списка РФ (`vk.com`, `yandex.ru`, `mail.ru`, `gosuslugi.ru`, `max.ru`, `*.yandexcloud.net`) и портам 443/80.
     - Health-Check: проверка доступности эндпоинта `https://yandex.ru/generate_204` с таймаутом до 2.5 сек.
     - Топ-10 серверов с наименьшим пингом.
  2. **`🚀 Быстрый / YouTube / Google` (Fast Global)**:
     - Мировые открытые базы с быстрыми VLESS-Reality, Shadowsocks, Trojan серверами (Германия, Нидерланды, Финляндия и др.).
     - Health-Check: проверка доступности `https://cp.cloudflare.com/generate_204` и `https://www.google.com/generate_204`.
     - Топ-15 скоростных узлов под 4K-видео и серфинг.
- **Поддержка 3 форматов подписок**:
  - `singbox.json` — конфигурация Sing-box с корневым селектором (`type: selector`) и группами авто-тестирования (`type: urltest`, проверка каждые 3 мин, `tolerance: 50`).
  - `clash.yaml` — профиль для Clash Meta / Mihomo с proxy-groups (Select + URL-Test).
  - `sub.txt` — Base64 raw-список со всеми отобранными серверами и понятными префиксами (`[🚀 Быстрый] ...` и `[⚡ Белые Списки] ...`).
- **Стильный веб-портал (`web/index.html`)**:
  - Адаптивный темный UI на Tailwind CSS (русский язык).
  - Подключение в 1 клик через Deep Links (`hiddify://`, `streisand://`, `v2rayng://`).
  - Динамический QR-код для сканирования камерой любого смартфона.
  - Удобные ссылки на скачивание клиентов для iOS, Android, Windows и macOS.
- **CI/CD Автоматизация**:
  - Ежечасный запуск по крону (`cron: '0 * * * *'`) и кнопка ручного запуска (`workflow_dispatch`).
  - Автоматический деплой директории `dist/` в GitHub Pages.

---

## 📁 Структура проекта

```text
├── .github/
│   └── workflows/
│       └── update.yml          # GitHub Actions CI/CD пайплайн
├── src/
│   ├── aggregator.py           # Асинхронный сборщик, тестер и генератор
│   └── template_singbox.json   # Шаблон Sing-box с DNS, Inbounds и Outbounds
├── web/
│   └── index.html              # Веб-интерфейс с Tailwind CSS и QR-кодом
├── requirements.txt            # Python-зависимости
└── README.md                   # Документация проекта
```

---

## 🚀 Пошаговое развертывание в GitHub (0 ₽)

### Шаг 1. Загрузка кода в GitHub
Создайте новый репозиторий на GitHub (например, `family-vpn`) и загрузите в него файлы проекта:
```bash
git init
git add .
git commit -m "feat: initial family vpn pipeline"
git branch -M main
git remote add origin https://github.com/kirik77/Family-Vpn.git
git push -u origin main
```

### Шаг 2. Включение GitHub Pages
1. Откройте ваш репозиторий на GitHub: [github.com/kirik77/Family-Vpn](https://github.com/kirik77/Family-Vpn).
2. Перейдите в **Settings** (Настройки) → **Pages**.
3. В разделе **Build and deployment** выберите:
   - **Source:** `GitHub Actions`.

### Шаг 3. Первый запуск
1. Перейдите во вкладку **Actions**.
2. В левой колонке выберите воркфлоу **«Update & Deploy Family VPN Subscriptions»**.
3. Нажмите кнопку **Run workflow** → **Run workflow**.
4. Через 30-45 секунд пайплайн завершит сборку и сайт станет доступен по адресу:
   `https://kirik77.github.io/Family-Vpn/`

---

## 📱 Инструкция для членов семьи

1. Отправьте родственникам ссылку на ваш сайт:  
   `https://kirik77.github.io/Family-Vpn/`
2. **На iPhone / iPad:**
   - Установите **Streisand** или **Hiddify** из App Store.
   - Откройте страницу сайта в Safari и нажмите **«Streisand (iOS)»** или **«Hiddify»**.
   - Подписка импортируется автоматически!
3. **На Android:**
   - Установите **Hiddify** или **v2rayNG**.
   - Нажмите соответствующую кнопку на сайте или отсканируйте QR-код в приложении.
4. **На ПК (Windows / macOS / Linux):**
   - Установите **Mihomo Party** или **Hiddify**.
   - Скопируйте ссылку на подписку и вставьте в клиент.

> 💡 **Рекомендация:** В настройках приложения клиента включите **«Автообновление подписки»** (Auto-update interval) на **60 минут**.

---

## 🛠️ Локальное тестирование

Для запуска и проверки работы сборщика на локальном компьютере:

```bash
# 1. Установка зависимостей
pip install -r requirements.txt

# 2. Запуск агрегатора
python src/aggregator.py

# 3. Проверка артефактов в папке dist/
ls -la dist/
```

После выполнения команды в папке `dist/` появятся:
- `dist/singbox.json` — конфигурация Sing-box.
- `dist/clash.yaml` — профиль Clash Meta.
- `dist/sub.txt` — Base64 raw-подписка.
- `dist/index.html` — портал для раздачи.
- `dist/stats.json` — метаданные пинга и времени обновления.
