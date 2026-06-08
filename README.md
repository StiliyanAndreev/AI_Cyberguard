# CyberGuard AI

Система за откриване на вътрешни заплахи (insider threats) чрез анализ на Git commits. Използва Google Gemini за семантичен анализ на промените в кода и Isolation Forest за поведенческо профилиране на разработчиците.

Дипломна работа към ТУ-София, ФКСТ, специалност "Компютърно и Софтуерно Инженерство".

## Какво прави

- Анализира Git diff на commits чрез LLM (Gemini 2.5 Flash) и оценява риска от 0 до 100
- Профилира разработчиците с Isolation Forest по характеристики като среден risk score, час на commit, weekend ratio
- Свързва откритите заплахи с техники от MITRE ATT&CK framework
- Визуализира резултатите в Streamlit dashboard
- Има защита с парола и поддръжка на български/английски език

## Технологии

- Python 3.11, Streamlit
- Google Gemini API
- scikit-learn (Isolation Forest)
- PostgreSQL 16
- Docker, Docker Compose
- GitPython

## Стартиране с Docker

Нужен е инсталиран Docker Desktop.

```bash
git clone https://github.com/youruser/AI_CyberGuard.git
cd AI_CyberGuard
cp .env.example .env
# попълни GEMINI_API_KEY и APP_PASSWORD в .env
docker compose up --build
```

Приложението става достъпно на http://localhost:8501.

## Стартиране без Docker

Изисква локален PostgreSQL с база `cyberguard`.

```bash
pip install -r requirements.txt
python -m streamlit run app/main.py
```

## Структура

```
AI_CYBERGUARD/
├── app/
│   └── main.py              # Streamlit UI
├── engine/
│   ├── ai_engine.py         # Интеграция с Gemini API
│   ├── git_handler.py       # Клониране и diff на репозитории
│   ├── db_handler.py        # PostgreSQL слой
│   ├── ueba_engine.py       # Isolation Forest профилиране
│   └── config.py            # Глобални константи
├── scripts/
│   └── threat_gen.py        # Генератор на тестови заплахи
├── data/                    # Клонирани репозитории
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Тест със симулирана заплаха

За демонстрация скриптът `threat_gen.py` създава Git хранилище с предварително вграден злонамерен commit:

```bash
python scripts/threat_gen.py
```

След това в приложението: Scan & Add Project → Local Path → `data/test_repo`. Gemini трябва да открие ексфилтрация на данни и да върне risk score около 90.

## Автор

Стилиян Андреев, ФН 121222179
Научен ръководител: доц. д-р Георги Запрянов