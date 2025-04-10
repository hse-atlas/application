# React OAuth Integration App

Это приложение на React, которое предоставляет функциональность для регистрации и входа через OAuth. Оно включает страницы для входа и регистрации с базовой валидацией и подтверждением пароля.

## Требования

Для запуска приложения на локальной машине вам нужно установить следующие зависимости:

- [Node.js](https://nodejs.org/) (рекомендуемая версия: 16.x или выше)
- [npm](https://www.npmjs.com/) (обычно устанавливается вместе с Node.js)

## Установка

1. Склонируйте репозиторий на свою локальную машину:

   ```bash
   git clone https://github.com/hse-atlas/web-application.git
   cd web-application/frontend
   ```

2. Установите зависимости:

   ```bash
   npm install
   ```

## Запуск приложения

Для запуска приложения в режиме разработки используйте команду:

```bash
npm start
```

Это откроет приложение в браузере по умолчанию на [http://localhost:3000](http://localhost:3000).

## Структура проекта

Вот как организована структура проекта:

```
frontend/
├── public/
│   └── index.html               # Главная HTML страница
├── src/
│   ├── components/             # Компоненты приложения
│   │   └── ...
│   ├── pages/                  # Старницы приложения
│   │   ├── Login.js            # Страница логина
│   │   ├── Register.js         # Страница регистрации
│   │   ├── Main.js             # Главная страница
│   │   ├── Profile.js          # Страница профиля
│   │   └── ...
│   ├── styles/                  # Стили
│   │   ├── Login.css            # Стили для страницы логина
│   │   ├── Register.css         # Стили для страницы регистрации
│   │   └── ...
│   ├── App.js                   # Главный компонент приложения
│   ├── index.js                 # Точка входа в приложение
│   └── ...
├── .gitignore                   # Файл для игнорирования файлов в Git
├── package.json                 # Зависимости и конфигурация проекта
└── README.md                    # Документация для разработчиков
```

## Используемые технологии

- **React** — для построения пользовательского интерфейса
- **Ant Design** — для компонентов UI
- **React Router** — для маршрутизации
- **CSS** — для стилизации приложения
- **Normalize.css** — для нормализации стилей браузера

### Описание разделов:

- **Требования** — описываются зависимости, которые нужны для работы приложения.
- **Установка** — инструкции по клонированию репозитория и установке зависимостей.
- **Запуск приложения** — инструкции по запуску проекта на локальной машине.
- **Структура проекта** — описание структуры папок и файлов, что поможет другим разработчикам понять, как организован проект.
- **Используемые технологии** — список технологий, используемых в проекте.
