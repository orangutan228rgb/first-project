# 🔐 Secure Messenger Crypto

<p align="center">
  <img src="https://nodejs.org/static/images/logo.svg" width="200" alt="Node.js Logo">
  <br>
  <strong>Библиотека для сквозного шифрования сообщений</strong>
</p>

<div align="center">
  
[🚀 Быстрый старт](#быстрый-старт) | 
[📚 Примеры](#примеры) | 
[🔧 API](#api) | 
[🧪 Тесты](#тесты)

</div>

## 🚀 Быстрый старт

```bash
git clone <repository-url>
cd secure-messenger-crypto
```

```javascript
const { MessengerCrypto, SecureMessenger } = require('./crypto-script');

// Простое шифрование
const crypto = new MessengerCrypto();
const key = crypto.generateKey();

const encrypted = crypto.encrypt("Привет мир!", key);
const decrypted = crypto.decrypt(encrypted, key);

console.log('Результат:', decrypted); // "Привет мир!"
```

📚 Примеры

🔑 Шифрование с паролем

```javascript
const crypto = new MessengerCrypto();
const password = "мой_пароль";
const keyData = crypto.deriveKeyFromPassword(password);

const encrypted = crypto.encrypt("Секретное сообщение", keyData.key);
const decrypted = crypto.decrypt(encrypted, keyData.key);

console.log('Дешифровано:', decrypted);
```

💬 Мессенджер с сессиями

```javascript
const messenger = new SecureMessenger();

// Создаем сессию между пользователями
const session = messenger.createSession("alice", "bob");

// Алиса отправляет сообщение
const encryptedMsg = messenger.sendMessage(
    session.sessionId, 
    "alice", 
    "Привет Боб!"
);

// Боб получает сообщение
const received = messenger.receiveMessage(encryptedMsg);
console.log(`${received.from}: ${received.message}`);
```

🛡️ Проверка целостности

```javascript
const crypto = new MessengerCrypto();
const key = crypto.generateKey();

// Шифруем с HMAC
const encrypted = crypto.encryptWithHMAC("Важные данные", key);

// Пытаемся подделать данные
encrypted.encryptedData = "поддельные_данные";

try {
    const decrypted = crypto.decryptWithHMAC(encrypted, key);
} catch (error) {
    console.log('Обнаружена подделка!'); // Сработает это
}
```

🔧 API

MessengerCrypto

Метод Описание
generateKey() Случайный ключ 256-bit
encrypt(text, key) Шифрует текст
decrypt(encrypted, key) Дешифрует текст
encryptWithHMAC(text, key) Шифрование с проверкой целостности

SecureMessenger

Метод Описание
createSession(user1, user2) Создает безопасную сессию
sendMessage(sessionId, from, message) Отправляет зашифрованное сообщение
receiveMessage(encrypted) Получает и дешифрует сообщение

🧪 Тесты

```bash
node crypto-script.js
```

Ожидаемый вывод:

```
Тест шифрования Messenger
Базовое шифрование Успех
Шифрование с паролем Успех
Симуляция мессенджера Успех
Проверка целостности Успех
```

---

<div align="center">

⬆️ Наверх | 
🚀 Быстрый старт| 
📚 Примеры

</div>

<script>
// Скрипт для плавной прокрутки
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth' });
        }
    });
});
</script>

<style>
a[href^="#"] {
    color: #007acc;
    text-decoration: none;
    padding: 5px 10px;
    border: 1px solid #007acc;
    border-radius: 5px;
    margin: 0 5px;
    transition: all 0.3s;
}
a[href^="#"]:hover {
    background-color: #007acc;
    color: white;
}
</style>

```
