const crypto = require('crypto');

class MessengerCrypto {
    constructor() {
        this.ALGORITHM = 'aes-256-gcm';
        this.KEY_LENGTH = 32;
        this.IV_LENGTH = 16;
        this.AUTH_TAG_LENGTH = 16;
        this.SALT_LENGTH = 64;
    }

    generateKey() {
        return crypto.randomBytes(this.KEY_LENGTH);
    }

    generateDHKeyPair() {
        const dh = crypto.createDiffieHellman(2048);
        const publicKey = dh.generateKeys();
        const privateKey = dh.getPrivateKey();
        
        return {
            publicKey: publicKey.toString('hex'),
            privateKey: privateKey.toString('hex')
        };
    }

    computeDHSecret(privateKey, otherPublicKey) {
        const dh = crypto.createDiffieHellman(2048);
        dh.setPrivateKey(Buffer.from(privateKey, 'hex'));
        return dh.computeSecret(Buffer.from(otherPublicKey, 'hex'));
    }

    deriveKeyFromPassword(password, salt = null) {
        const usedSalt = salt || crypto.randomBytes(this.SALT_LENGTH);
        const key = crypto.pbkdf2Sync(
            password, 
            usedSalt, 
            100000,
            this.KEY_LENGTH, 
            'sha512'
        );
        
        return {
            key,
            salt: usedSalt.toString('hex')
        };
    }

    encrypt(text, key, additionalData = null) {
        try {
            const iv = crypto.randomBytes(this.IV_LENGTH);
            const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv, {
                authTagLength: this.AUTH_TAG_LENGTH
            });
            
            if (additionalData) {
                cipher.setAAD(Buffer.from(additionalData));
            }
            
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const authTag = cipher.getAuthTag();
            
            return {
                iv: iv.toString('hex'),
                encryptedData: encrypted,
                authTag: authTag.toString('hex'),
                algorithm: this.ALGORITHM,
                timestamp: Date.now()
            };
        } catch (error) {
            throw new Error(`Ошибка шифрования: ${error.message}`);
        }
    }

    decrypt(encryptedObject, key, additionalData = null) {
        try {
            const { iv, encryptedData, authTag } = encryptedObject;
            
            if (!iv || !encryptedData || !authTag) {
                throw new Error('Неверный формат зашифрованных данных');
            }
            
            const ivBuffer = Buffer.from(iv, 'hex');
            const authTagBuffer = Buffer.from(authTag, 'hex');
            const decipher = crypto.createDecipheriv(
                this.ALGORITHM, 
                key, 
                ivBuffer, 
                { authTagLength: this.AUTH_TAG_LENGTH }
            );
            
            decipher.setAuthTag(authTagBuffer);
            
            if (additionalData) {
                decipher.setAAD(Buffer.from(additionalData));
            }
            
            let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            throw new Error(`Ошибка дешифрования: ${error.message}`);
        }
    }

    createHMAC(data, key) {
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(data);
        return hmac.digest('hex');
    }

    verifyHMAC(data, receivedHMAC, key) {
        const calculatedHMAC = this.createHMAC(data, key);
        return crypto.timingSafeEqual(
            Buffer.from(calculatedHMAC, 'hex'),
            Buffer.from(receivedHMAC, 'hex')
        );
    }

    encryptWithHMAC(text, encryptionKey, hmacKey = null) {
        const usedHMACKey = hmacKey || encryptionKey;
        const encrypted = this.encrypt(text, encryptionKey);
        const hmacData = encrypted.iv + encrypted.encryptedData;
        encrypted.hmac = this.createHMAC(hmacData, usedHMACKey);
        return encrypted;
    }

    decryptWithHMAC(encryptedObject, encryptionKey, hmacKey = null) {
        const usedHMACKey = hmacKey || encryptionKey;
        const hmacData = encryptedObject.iv + encryptedObject.encryptedData;
        if (!this.verifyHMAC(hmacData, encryptedObject.hmac, usedHMACKey)) {
            throw new Error('HMAC проверка не пройдена - данные повреждены');
        }
        return this.decrypt(encryptedObject, encryptionKey);
    }
}

class SecureMessenger {
    constructor() {
        this.crypto = new MessengerCrypto();
        this.sessions = new Map();
    }

    createSession(user1, user2) {
        const sessionId = `${user1}-${user2}`;
        const user1Keys = this.crypto.generateDHKeyPair();
        const user2Keys = this.crypto.generateDHKeyPair();
        const sharedSecret1 = this.crypto.computeDHSecret(
            user1Keys.privateKey, 
            user2Keys.publicKey
        );
        const sharedSecret2 = this.crypto.computeDHSecret(
            user2Keys.privateKey, 
            user1Keys.publicKey
        );
        
        if (!sharedSecret1.equals(sharedSecret2)) {
            throw new Error('Ошибка в обмене ключами по Диффи-Хеллману');
        }
        
        const session = {
            sessionId,
            sharedSecret: sharedSecret1,
            users: [user1, user2],
            createdAt: Date.now()
        };
        
        this.sessions.set(sessionId, session);
        
        return {
            sessionId,
            user1: { publicKey: user1Keys.publicKey },
            user2: { publicKey: user2Keys.publicKey }
        };
    }

    sendMessage(sessionId, fromUser, message) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            throw new Error('Сессия не найдена');
        }
        
        if (!session.users.includes(fromUser)) {
            throw new Error('Пользователь не принадлежит этой сессии');
        }
        
        const encryptedMessage = this.crypto.encryptWithHMAC(
            message, 
            session.sharedSecret
        );
        
        encryptedMessage.sender = fromUser;
        encryptedMessage.sessionId = sessionId;
        encryptedMessage.messageId = crypto.randomBytes(16).toString('hex');
        
        return encryptedMessage;
    }

    receiveMessage(encryptedMessage) {
        const session = this.sessions.get(encryptedMessage.sessionId);
        if (!session) {
            throw new Error('Сессия не найдена');
        }
        
        const decryptedMessage = this.crypto.decryptWithHMAC(
            encryptedMessage, 
            session.sharedSecret
        );
        
        return {
            from: encryptedMessage.sender,
            message: decryptedMessage,
            timestamp: encryptedMessage.timestamp,
            messageId: encryptedMessage.messageId
        };
    }
}

function demo() {
    console.log('Тест шифрования Messenger');
    
    const messenger = new SecureMessenger();
    const crypto = new MessengerCrypto();

    const secretKey = crypto.generateKey();
    const originalMessage = "Тестовое сообщение";
    
    const encrypted = crypto.encrypt(originalMessage, secretKey);
    const decrypted = crypto.decrypt(encrypted, secretKey);
    
    console.log('Базовое шифрование', originalMessage === decrypted ? 'Успех' : 'Ошибка');

    const password = 'test_password';
    const keyData = crypto.deriveKeyFromPassword(password);
    const secretMessage = "Сообщение с паролем";
    
    const encryptedWithPassword = crypto.encrypt(secretMessage, keyData.key);
    const decryptedWithPassword = crypto.decrypt(encryptedWithPassword, keyData.key);
    
    console.log('Шифрование с паролем', secretMessage === decryptedWithPassword ? 'Успех' : 'Ошибка');

    const session = messenger.createSession('alice', 'bob');
    const aliceMessage = "Привет Боб";
    
    const encryptedAliceMessage = messenger.sendMessage(session.sessionId, 'alice', aliceMessage);
    const bobReceived = messenger.receiveMessage(encryptedAliceMessage);
    
    console.log('Симуляция мессенджера', aliceMessage === bobReceived.message ? 'Успех' : 'Ошибка');

    try {
        const tamperedMessage = { ...encryptedAliceMessage };
        tamperedMessage.encryptedData = tamperedMessage.encryptedData.replace('a', 'b');
        messenger.receiveMessage(tamperedMessage);
        console.log('Проверка целостности', 'Ошибка');
    } catch (error) {
        console.log('Проверка целостности', 'Успех');
    }
}

if (require.main === module) {
    demo();
}
// ты умный пупс?
module.exports = { MessengerCrypto, SecureMessenger };
