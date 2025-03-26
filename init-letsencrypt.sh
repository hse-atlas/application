#!/bin/bash

# Создаём необходимые директории
mkdir -p ./certbot/{www,conf}

# Временный запуск nginx для верификации
docker-compose up -d frontend

# Получаем сертификат (новый синтаксис)
docker-compose run --rm --entrypoint "certbot certonly --webroot --webroot-path /var/www/certbot --register-unsafely-without-email --agree-tos -d atlas.appweb.space" certbot

# Проверяем результат
if [ -f "./certbot/conf/live/atlas.appweb.space/fullchain.pem" ]; then
    echo "✅ Сертификат успешно получен!"
    docker-compose down && docker-compose up -d
else
    echo "❌ Ошибка при получении сертификата"
    docker-compose logs certbot
fi