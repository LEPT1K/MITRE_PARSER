# 🚀 MITRE PARSER 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)

**MITRE PARSER** – это мощный инструмент для автоматического сбора, парсинга и обогащения данных из ключевых баз знаний в области кибербезопасности:
- [MITRE ATT&CK®](https://attack.mitre.org/) (техники атак)
- [CAPEC™](https://capec.mitre.org/) (шаблоны атак)
- [CWE™](https://cwe.mitre.org/) (слабые места ПО)
- [CVE®](https://nvd.nist.gov/) (публичные уязвимости)

Результатом работы являются **взаимосвязанные JSON-файлы** с заполненными перекрёстными ссылками и рекомендациями по устранению уязвимостей (`mitigations`), готовые для использования в аналитических системах, SIEM, SOAR, Threat Intelligence платформах или собственных исследованиях.

---

## ✨ Возможности

- 🔄 **Автоматическая загрузка** последних версий баз с официальных источников.
- 🧩 **Глубокий парсинг** исходных форматов (XML, STIX 2.1, JSON).
- 🔗 **Интеллектуальное связывание данных**:
  - `CAPEC ↔ ATT&CK`
  - `CVE → CWE → CAPEC → ATT&CK`
  - Обратное распространение связей и мер защиты.
- 🛡️ **Заполнение полей `mitigations`** во всех выходных файлах за счёт анализа цепочек связей.
- 🌐 **Опциональный перевод** описаний и рекомендаций на русский язык.
- ⚙️ **Гибкая настройка** через конфигурационный файл (лимиты записей, режим перевода, пути).
- 📦 **Чистый и структурированный JSON** на выходе, готовый к импорту в БД или аналитику.

---

## 📂 Структура проекта

```
MITRE_PARSER_V2/
├── src/
│   ├── parsers/               # Парсеры для каждого источника
│   │   ├── base.py
│   │   ├── attack_parser.py
│   │   ├── capec_parser.py
│   │   ├── cwe_parser.py
│   │   └── cve_parser.py
│   ├── config.py              # Настройки (лимиты, пути, перевод)
│   ├── downloader.py          # Загрузка файлов с повторными попытками
│   ├── cross_linker.py        # Логика связывания и обогащения данных
│   ├── normalizer.py          # Очистка и нормализация JSON
│   ├── translator.py          # Интеграция с переводчиком
│   └── main.py                # Точка входа
├── output/                    # Результаты работы (создаётся автоматически)
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 🛠 Установка и запуск

### 1. Клонирование репозитория
```bash
git clone https://github.com/yourusername/MITRE_PARSER_V2.git
cd MITRE_PARSER_V2
```

### 2. Создание виртуального окружения (рекомендуется)
```bash
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows
```

### 3. Установка зависимостей
```bash
pip install -r requirements.txt
```

### 4. Настройка (опционально)
Отредактируйте `src/config.py`, чтобы:
- Включить/выключить перевод (`ENABLE_TRANSLATION`)
- Ограничить количество обрабатываемых записей (`MAX_..._RECORDS`)
- Изменить выходную директорию (`OUTPUT_DIR`)

### 5. Запуск
```bash
python src/main.py
```

После завершения работы в папке `output/` появятся файлы:
- `capec_database.json`
- `cwe_database.json`
- `cve_database.json`
- `mitre_attack.json`

---

## ⚙️ Конфигурация (`config.py`)

```python
class Config:
    # Лимиты записей (0 = без ограничений)
    MAX_CAPEC_RECORDS = 0
    MAX_CWE_RECORDS   = 0
    MAX_CVE_RECORDS   = 1500
    MAX_ATTACK_RECORDS = 0

    # Перевод описаний на русский язык
    ENABLE_TRANSLATION = False

    # Папка для сохранения результатов
    OUTPUT_DIR = Path(__file__).parent.parent / "output"
```

---

## 📄 Формат выходных данных

### `mitre_attack.json`
```json
{
  "id": "T1055.011",
  "name": "Extra Window Memory Injection",
  "tactic": "Defense Evasion",
  "description": "...",
  "platforms": ["Windows"],
  "related_cwe": [],
  "related_capec": [],
  "requires_service": ["api_service", "windows_os"],
  "detection": "",
  "mitigations": [
    "Behavior Prevention on Endpoint ..."
  ]
}
```

### `capec_database.json`
```json
{
  "id": "CAPEC-1",
  "name": "Accessing Functionality Not Properly Constrained by ACLs",
  "description": "...",
  "severity": "HIGH",
  "related_cwe": ["CWE-276", "CWE-285"],
  "related_mitre": [],
  "prerequisites": ["..."],
  "mitigations": ["In a J2EE setting, administrators can associate a role ..."]
}
```

### `cwe_database.json`
```json
{
  "id": "CWE-1021",
  "name": "Improper Restriction of Rendered UI Layers or Frames",
  "description": "...",
  "category": "unknown",
  "related_capec": ["CAPEC-103", "CAPEC-181"],
  "mitigation": "Implementation The use of X-Frame-Options ...",
  "requires_technology": [],
  "detection_methods": ["automated_static_analysis..."]
}
```

### `cve_database.json`
```json
{
  "id": "CVE-2005-3817",
  "description": "Multiple SQL injection vulnerabilities ...",
  "severity": "UNKNOWN",
  "cvss_score": 7.5,
  "affected_software": ["softbizscripts web_hosting_directory_script"],
  "attack_type": "sql_injection",
  "related_cwe": ["CWE-89"],
  "related_capec": [],
  "related_mitre": [],
  "requires_service": [],
  "requires_port": [],
  "prerequisites": [],
  "mitigations": [
    "Architecture and Design Libraries or Frameworks Use a vetted library ..."
  ]
}
```

---

## 🔬 Примеры использования

- **Анализ цепочек атак**: сопоставьте технику ATT&CK → CAPEC → CWE → CVE, чтобы оценить реальные уязвимости, эксплуатируемые данной техникой.
- **Обогащение SIEM**: загрузите JSON-файлы в Elasticsearch и стройте дашборды по рекомендациям MITRE.
- **Генерация отчётов**: автоматически создавайте документы с описанием угроз и мерами защиты.
- **Обучение и исследования**: используйте структурированные данные для создания учебных материалов или научных работ.

---

## 📌 Примечания

- Поля могут оставаться пустыми, если соответствующие связи отсутствуют в исходных базах MITRE/NVD.
- Для включения перевода на русский язык установите `ENABLE_TRANSLATION = True` в `config.py`. Будет использоваться библиотека `googletrans` (требуется интернет-соединение).
- При первом запуске рекомендуется установить лимиты записей для тестирования (например, `MAX_CVE_RECORDS = 100`).

---

## 📜 Лицензия

Проект распространяется под лицензией **MIT**.  
Вы можете свободно использовать, модифицировать и распространять код при условии сохранения уведомления об авторских правах.

---

## 🙏 Благодарности

- [MITRE Corporation](https://www.mitre.org/) за создание и поддержку CAPEC, CWE и ATT&CK.
- [NIST NVD](https://nvd.nist.gov/) за предоставление фидов CVE.
- Всем контрибьюторам и пользователям, помогающим улучшать проект.
