FROM python:3.10-slim

# 1. Инсталираме Git и инструменти за мрежата
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# 2. Работна директория
WORKDIR /app

# 3. Инсталиране на библиотеки
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Копиране на проекта
COPY . .

# 5. Работна папка за клонирани репозитории
RUN mkdir -p data/clones

# 6. Порт за Streamlit
EXPOSE 8501

# 7. Стартиране
CMD ["streamlit", "run", "app/main.py", "--server.port=8501", "--server.address=0.0.0.0"]