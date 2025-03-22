FROM python:3.9-alpine

# Установка системных зависимостей
RUN apk add --no-cache \
    build-base \
    postgresql-client \
    redis \
    bash \
    libpq-dev \
    linux-headers \
    gcc \
    musl-dev

# Отключаем буферизацию вывода
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random

# Установка рабочей директории
WORKDIR /app

# Копируем файлы зависимостей и устанавливаем их
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Копируем весь проект в рабочую директорию
COPY . .

# Создаем директорию для логов
RUN mkdir -p /app/logs

# Даем права на выполнение entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Открываем порт 8000
EXPOSE 8000

# Запускаем приложение через entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]