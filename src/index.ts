var CryptoToolkit;
(function (CryptoToolkit) {
    class CryptoUtils {
        static EncryptionKey;
        static EncryptionIV;
        static enc = new TextEncoder();
        static dec = new TextDecoder();

        // Generate a new key pair for RSA-OAEP
        static async generateKey() {
            return await window.crypto.subtle.generateKey({
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: { name: 'SHA-256' }, // The hash algorithm used for RSA-OAEP
            }, true, ["encrypt", "decrypt"]);
        }

        // Export the public key in JWK format
        static async exportPublicKey() {
            const keys = await this.generateKey();
            return await window.crypto.subtle.exportKey('jwk', keys.publicKey);
        }

        // Export the private key in JWK format
        static async exportPrivateKey() {
            const keys = await this.generateKey();
            return await window.crypto.subtle.exportKey('jwk', keys.privateKey);
        }

        // Import a public key from JWK format
        static async importPublicKey(jwk) {
            return await window.crypto.subtle.importKey(
                "jwk",
                jwk,
                { name: "RSA-OAEP", hash: { name: "SHA-256" } }, // Import key with RSA-OAEP parameters
                true,
                ["encrypt"]
            );
        }

        // Import a private key from JWK format
        static async importPrivateKey(jwk) {
            return await window.crypto.subtle.importKey(
                "jwk",
                jwk,
                { name: "RSA-OAEP", hash: { name: "SHA-256" } }, // Import key with RSA-OAEP parameters
                true,
                ["decrypt"]
            );
        }

        // Encrypt data using RSA-OAEP
        static async encrypt(data) {
            const publicKey = await this.importPublicKey(await this.exportPublicKey());
            return window.crypto.subtle.encrypt({
                name: "RSA-OAEP",
            }, publicKey, new TextEncoder().encode(data));
        }

        // Decrypt data using RSA-OAEP
        static async decrypt(encryptedData) {
            const privateKey = await this.importPrivateKey(await this.exportPrivateKey());
            return window.crypto.subtle.decrypt({
                name: "RSA-OAEP",
            }, privateKey, encryptedData);
        }

        // Encrypt data using AES-GCM and store it
        static async encryptAndStore(key, data, storage = 'localStorage') {
            const encryptedData = await this.encryptWithAES(new TextEncoder().encode(data));
            window[storage].setItem(key, JSON.stringify(Array.from(new Uint8Array(encryptedData))));
        }

        // Decrypt data from storage using AES-GCM
        static async decryptFromStorage(key, storage = 'localStorage') {
            const encryptedData = JSON.parse(window[storage].getItem(key) || '[]');
            if (encryptedData.length === 0) return null;
            const encryptedArray = new Uint8Array(encryptedData);
            const decryptedData = await this.decryptWithAES(encryptedArray);
            return this.dec.decode(decryptedData);
        }

        // Encrypt data using AES-GCM
        static async encryptWithAES(data) {
            const iv = this.generateRandomIV();
            const key = await this.importAESKey();
            return window.crypto.subtle.encrypt({
                name: "AES-GCM",
                iv: iv,
                tagLength: 128, // AES-GCM tag length
            }, key, data);
        }

        // Decrypt data using AES-GCM
        static async decryptWithAES(encryptedData) {
            const iv = this.generateRandomIV(); // Use the same IV for decryption
            const key = await this.importAESKey();
            return window.crypto.subtle.decrypt({
                name: "AES-GCM",
                iv: iv,
                tagLength: 128, // AES-GCM tag length
            }, key, encryptedData);
        }

        // Import or generate an AES key for AES-GCM encryption/decryption
        static async importAESKey() {
            const key = await window.crypto.subtle.generateKey({
                name: 'AES-GCM',
                length: 256, // Key length in bits
            }, true, ["encrypt", "decrypt"]);
            return key;
        }

        // Generate a random IV for AES-GCM
        static generateRandomIV(length = 12) {
            const iv = new Uint8Array(length);
            window.crypto.getRandomValues(iv);
            return iv;
        }

        // Hash a string using MD5 (Note: MD5 is not supported by Web Crypto API, consider using other libraries)
        static async hashMD5(data) {
            const encoder = new TextEncoder();
            const buffer = encoder.encode(data);
            const hashBuffer = await crypto.subtle.digest('MD5', buffer); // MD5 is not supported directly
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }

        // Hash a string using SHA-512
        static async hashSHA512(data) {
            const encoder = new TextEncoder();
            const buffer = encoder.encode(data);
            const hashBuffer = await crypto.subtle.digest('SHA-512', buffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }
    }

    CryptoToolkit.CryptoUtils = CryptoUtils;
})(CryptoToolkit || (CryptoToolkit = {}));
