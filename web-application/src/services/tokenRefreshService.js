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
      // Получаем текущий токен
      const token = localStorage.getItem('access_token');
      if (!token) return;

      // Декодируем его для проверки
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(
        atob(base64).split('').map(c => {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join('')
      );

      const { exp } = JSON.parse(jsonPayload);
      if (!exp) return;

      const currentTime = Math.floor(Date.now() / 1000);
      const expiresIn = exp - currentTime;

      // Если токен скоро истечет, обновляем его и показываем уведомление
      if (expiresIn < 300) {
        const oldToken = token;
        await checkAndRefreshTokenIfNeeded();
        const newToken = localStorage.getItem('access_token');

        // Проверяем, действительно ли токен изменился
        if (this.showNotifications && oldToken !== newToken) {
          message.info({
            content: 'Your session was automatically extended to keep you logged in.',
            duration: 3,
            style: { marginTop: '20px' },
          });
        }
      }
    } catch (error) {
      console.error('Error in token check with notification:', error);
    }
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
tokenRefreshService.debug = function() {
  this.toggleNotifications(true);
  console.log('%c[Token Service] 🔍 Debug mode enabled. You will see notifications when tokens are refreshed.',
    'background: #e6f7ff; color: #1890ff; padding: 4px; border-radius: 2px; font-weight: bold;');
};

export default tokenRefreshService;