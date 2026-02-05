import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // 128 bits
const AUTH_TAG_LENGTH = 16; // 128 bits
const KEY_LENGTH = 32; // 256 bits

/**
 * Get encryption key from environment variable
 * Ensures key is properly formatted and hashed to correct length
 */
function getEncryptionKey(): Buffer {
    const key = process.env.ENCRYPTION_KEY;

    if (!key) {
        throw new Error('ENCRYPTION_KEY environment variable is not set');
    }

    if (key.length < 32) {
        throw new Error('ENCRYPTION_KEY must be at least 32 characters long');
    }

    // Use SHA-256 to derive a key of exactly 32 bytes
    return crypto.createHash('sha256').update(key).digest();
}

/**
 * Encrypt data using AES-256-GCM
 * @param text - Plain text to encrypt
 * @returns Object containing encrypted data, IV, and auth tag
 */
export function encrypt(text: string): {
    encryptedData: string;
    iv: string;
    authTag: string;
} {
    const key = getEncryptionKey();
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return {
        encryptedData: encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
    };
}

/**
 * Decrypt data using AES-256-GCM
 * @param encryptedData - Encrypted text in hex format
 * @param iv - Initialization vector in hex format
 * @param authTag - Authentication tag in hex format
 * @returns Decrypted plain text
 */
export function decrypt(
    encryptedData: string,
    iv: string,
    authTag: string
): string {
    const key = getEncryptionKey();
    const decipher = crypto.createDecipheriv(
        ALGORITHM,
        key,
        Buffer.from(iv, 'hex')
    );

    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

/**
 * Generate a random token (for email verification, password reset, etc.)
 * @param length - Length of the token in bytes (default: 32)
 * @returns Random token as hex string
 */
export function generateRandomToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Hash a token using SHA-256 (for storing refresh tokens)
 * @param token - Token to hash
 * @returns Hashed token
 */
export function hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
}