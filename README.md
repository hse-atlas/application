# Atlas

**Atlas** — это веб-приложение для настройки и интеграции OAuth. Оно позволяет администраторам добавлять в свои проекты авторизацию через сервис Atlas.

---

## Оглавление

1. [Основные функции](#основные-функции)
2. [Технологии](#технологии)
3. [Установка и запуск](#установка-и-запуск)
4. [API](#api)
5. [Лицензия](#лицензия)

---

## Основные функции

- **Управление проектами:**
  - Создание, редактирование и удаление проектов.
  - Просмотр списка проектов и их деталей.
- **Управление пользователями:**
  - Изменение ролей пользователей (администратор, пользователь).
  - Удаление пользователей из проектов.
- **Аутентификация и авторизация:**
  - Регистрация и вход в систему.
  - Защита маршрутов на основе ролей.

---

## Технологии

### Бэкенд

- **Язык программирования:** Python
- **Фреймворк:** FastAPI
- **База данных:** PostgreSQL
- **ORM:** SQLAlchemy (асинхронный режим)
- **Аутентификация:** JWT (JSON Web Tokens)
- **Документация API:** Swagger (автоматически генерируется FastAPI)

### Фронтенд

- **Язык программирования:** JavaScript
- **Фреймворк:** React
- **Библиотеки:**
  - **UI:** Ant Design
  - **Маршрутизация:** React Router
  - **Управление состоянием:** Redux
  - **HTTP-клиент:** Axios

---

## Установка и запуск

1. **Клонируйте репозиторий:**

   ```bash
   git clone https://github.com/hse-atlas/application
   cd application
   ```

2. **Запустить приложение в Docker:**

   ```bash
   docker-compose up --build
   ```

3. **Документация API:**

   - После запуска сервера откройте в браузере:
     ```
     http://localhost:8000/docs
     ```

4. **Откройте приложение в браузере:**
   ```
   http://localhost:3000
   ```

---

## API

### Основные эндпоинты

- **Аутентификация:**

  - `POST /register` — регистрация пользователя.
  - `POST /login` — вход в систему.
  - `POST /refresh` — обновление токена.

- **Проекты:**

  - `GET /projects` — список всех проектов.
  - `POST /projects` — создание нового проекта.
  - `PUT /projects/{project_id}` — обновление проекта.
  - `DELETE /projects/{project_id}` — удаление проекта.

- **Пользователи:**

  - `GET /projects/{project_id}/users` — список пользователей проекта.
  - `PUT /projects/{project_id}/users/{user_id}/role` — изменение роли пользователя.
  - `DELETE /projects/{project_id}/users/{user_id}` — удаление пользователя из проекта.

---

## Лицензия

Этот проект распространяется под лицензией MIT. Подробности см. в файле [LICENSE RU](https://ru.wikipedia.org/wiki/Лицензия_MIT).

---

## Руководитель

- [Vladimir Denisov](https://github.com/vdenisov-pro)

---

## Авторы

- [Dandamaev](https://github.com/Dandamaev)
- [RobertoRoz](https://github.com/RobertoRoz)
- [basuta13](https://github.com/basuta13)
