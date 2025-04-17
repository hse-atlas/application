// tokenRefreshService.js
import { checkAndRefreshTokenIfNeeded } from '../api'; // Импортируем функцию проверки/обновления
import { message } from 'antd';
import tokenService from './tokenService'; // Импортируем для проверки токена

// Интервал проверки токена (в миллисекундах)
const TOKEN_CHECK_INTERVAL = 60000; // Проверять каждую минуту

class TokenRefreshService {
  constructor() {
    this.intervalId = null;
    this.isActive = false;
    this.showNotifications = false;
    this.isChecking = false; // Флаг для предотвращения параллельных проверок
  }

  toggleNotifications(show) {
    this.showNotifications = show;
  }

  start() {
    // Запускаем только если есть токен и сервис не активен
    if (this.isActive || !tokenService.isAuthenticated()) {
      console.log('[RefreshService] Not starting: Service active or user not authenticated.');
      return;
    }

    console.log('[RefreshService] Starting...');
    this.isActive = true;

    // Запускаем первую проверку немедленно, но асинхронно
    this._checkToken();

    // Устанавливаем интервал
    this.intervalId = setInterval(() => {
      this._checkToken();
    }, TOKEN_CHECK_INTERVAL);

    console.log(`[RefreshService] Started with interval ${TOKEN_CHECK_INTERVAL / 1000}s.`);
  }

  async _checkToken() {
    // Предотвращаем запуск новой проверки, если предыдущая еще идет
    if (this.isChecking) {
      console.debug('[RefreshService] Check already in progress, skipping interval.');
      return;
    }

    // Проверяем, есть ли вообще токен, чтобы не гонять проверку зря
    if (!tokenService.isAuthenticated()) {
      console.debug('[RefreshService] No token found, stopping service.');
      this.stop();
      return;
    }

    this.isChecking = true;
    console.debug('[RefreshService] Performing token check...');

    try {
      const oldToken = tokenService.getAccessToken(); // Запоминаем старый токен до проверки/обновления
      await checkAndRefreshTokenIfNeeded(); // Вызываем функцию проверки и возможного обновления
      const newToken = tokenService.getAccessToken(); // Получаем токен после проверки/обновления

      // Показываем уведомление, если токен реально обновился и уведомления включены
      // Проверяем и старый, и новый, т.к. токен мог быть удален при ошибке
      if (this.showNotifications && oldToken && newToken && oldToken !== newToken) {
        message.info({
          content: 'Your session was automatically extended.',
          duration: 3,
          style: { marginTop: '20px' },
        });
        console.log('[RefreshService] Session extended notification shown.');
      }
    } catch (error) {
      // Ошибки логируются внутри checkAndRefreshTokenIfNeeded или refreshAuthToken
      console.error('[RefreshService] Error during scheduled check:', error.message);
      // Не останавливаем сервис при ошибке, он попробует снова
    } finally {
      this.isChecking = false; // Сбрасываем флаг
      console.debug('[RefreshService] Token check finished.');
    }
  }

  stop() {
    if (!this.isActive) return;

    clearInterval(this.intervalId);
    this.intervalId = null;
    this.isActive = false;
    this.isChecking = false; // Сбрасываем флаг при остановке
    console.log('[RefreshService] Stopped.');
  }

  registerEventListeners() {
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        console.debug('[RefreshService] Tab hidden, stopping service.');
        this.stop();
      } else {
        // При возвращении фокуса - запускаем сервис (он сам проверит токен)
        console.debug('[RefreshService] Tab focused, starting service.');
        this.start();
      }
    });

    window.addEventListener('online', () => {
      // При восстановлении сети - запускаем сервис
      console.debug('[RefreshService] Network online, ensuring service is running.');
      this.start();
    });

    // Слушаем событие logout, чтобы остановить сервис
    window.addEventListener('logout', () => {
      console.debug('[RefreshService] Logout event detected, stopping service.');
      this.stop();
    });
    // Слушаем событие login, чтобы запустить сервис
    window.addEventListener('login', () => {
      console.debug('[RefreshService] Login event detected, starting service.');
      this.start();
    });
  }
}

// --- Экспорт и дебаг ---
const tokenRefreshService = new TokenRefreshService();
tokenRefreshService.registerEventListeners();

tokenRefreshService.debug = function () {
  this.toggleNotifications(true);
  console.log('%c[RefreshService] 🔍 Debug mode enabled.', 'background: #e6f7ff; color: #1890ff; padding: 4px; border-radius: 2px; font-weight: bold;');
};

export default tokenRefreshService;