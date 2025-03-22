#!/bin/sh

set -e

# Ожидание запуска базы данных
echo "Ожидание запуска базы данных..."
while ! pg_isready -h "$PASS_DB_HOST" -p "$PASS_DB_PORT" -U "$PASS_DB_USER"; do
  sleep 0.5
done
echo "База данных запущена!"

echo "Инициализация базы данных..."
python init_db.py

# Ожидание запуска Redis
echo "Ожидание запуска Redis..."
until redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" ping | grep PONG; do
  sleep 0.5
done
echo "Redis запущен!"

# Запуск приложения
echo "Запуск приложения..."
exec uvicorn app.main:application --host 0.0.0.0 --port 8000 ${DEBUG_FLAG:+--reload}