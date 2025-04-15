import { checkAndRefreshTokenIfNeeded } from '../api';
import { message } from 'antd';

// Интервал проверки токена (в миллисекундах)
const TOKEN_CHECK_INTERVAL = 60000; // Проверять каждую минуту

class TokenRefreshService {
  constructor() {
    this.intervalId = null;
    this.isActive = false;
    this.showNotifications = false; // Флаг для управления уведомлениями
  }

  // Включение/выключение уведомлений
  toggleNotifications(show) {
    this.showNotifications = show;
  }

  // Запуск сервиса автоматического обновления токенов
  start() {
    if (this.isActive) return;

    // Проверяем токен при старте
    this._checkTokenWithNotification();

    // Устанавливаем интервал для регулярной проверки
    this.intervalId = setInterval(() => {
      this._checkTokenWithNotification();
    }, TOKEN_CHECK_INTERVAL);

    this.isActive = true;
    console.log('Token refresh service started');
  }

  // Приватный метод для проверки токена с возможными уведомлениями
  async _checkTokenWithNotification() {
    try {
      const token = localStorage.getItem('access_token');
      if (!token) {
        this._handleSessionExpired();
        return;
      }

      const { exp } = this._decodeToken(token);
      if (!exp) return;

      const currentTime = Math.floor(Date.now() / 1000);
      const expiresIn = exp - currentTime;

      if (expiresIn < 300) { // 5 минут
        try {
          // Отменяем предыдущий незавершенный запрос, если есть
          if (this._refreshRequest && this._refreshRequest.cancel) {
            this._refreshRequest.cancel('New refresh attempt');
          }

          // Создаем новый токен отмены
          const cancelToken = new axios.CancelToken(c => {
            this._refreshRequest = { cancel: c };
          });

          const oldToken = token;
          const success = await checkAndRefreshTokenIfNeeded({ cancelToken });

          if (!success) {
            throw new Error('Token refresh failed');
          }

          const newToken = localStorage.getItem('access_token');
          if (this.showNotifications && oldToken !== newToken) {
            message.info('Session was extended');
          }
        } catch (error) {
          if (axios.isCancel(error)) {
            console.log('Refresh request canceled:', error.message);
          } else {
            console.error('Token refresh error:', error);
            this._handleSessionExpired();
          }
        } finally {
          this._refreshRequest = null;
        }
      }
    } catch (error) {
      console.error('Token check error:', error);
      this._handleSessionExpired();
    }
  }

  _handleSessionExpired() {
    if (this.showNotifications) {
      message.error('Session expired. Please login again.');
    }
    this.stop();
    // Дополнительные действия: очистка хранилища, редирект на логин и т.д.
    localStorage.removeItem('access_token');
    window.location.href = '/login';
  }

  // Остановка сервиса
  stop() {
    if (!this.isActive) return;

    clearInterval(this.intervalId);
    this.intervalId = null;
    this.isActive = false;
    console.log('Token refresh service stopped');
  }

  // Регистрация обработчиков событий для приостановки/возобновления проверки
  registerEventListeners() {
    // Приостанавливаем проверку, когда вкладка неактивна
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.stop();
      } else {
        this.start(); // Возобновляем и сразу проверяем токен
      }
    });

    // Проверяем токен при возвращении онлайн
    window.addEventListener('online', () => {
      checkAndRefreshTokenIfNeeded();
    });
  }
}

// Создаем единственный экземпляр сервиса
const tokenRefreshService = new TokenRefreshService();
tokenRefreshService.registerEventListeners();

// Публичный метод для включения уведомлений в консоли разработчика
tokenRefreshService.debug = function () {
  this.toggleNotifications(true);
  console.log('%c[Token Service] 🔍 Debug mode enabled. You will see notifications when tokens are refreshed.',
    'background: #e6f7ff; color: #1890ff; padding: 4px; border-radius: 2px; font-weight: bold;');
};

export default tokenRefreshService;