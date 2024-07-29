/// <reference types="jquery" />
/// <reference path="../typings/dx.all.d.ts" />
var CryptoToolkit;
(function (CryptoToolkit) {
    class CryptoUtils {
        static EncryptionKey;
        static EncryptionIV;
        static enc = new TextEncoder();
        
        static async exportPublicKey() {
            var getData = await this.generateKey();
            return await window.crypto.subtle.exportKey('jwk', getData.publicKey);
        }
        
        static async exportPrivateKey() {
            var getData = await this.generateKey();
            return await window.crypto.subtle.exportKey('jwk', getData.privateKey);
        }
        
        static async importPublicKey() {
            var getData = await this.exportPublicKey();
            return await window.crypto.subtle.importKey("jwk", getData, { name: "RSA-OAEP", hash: { name: "SHA-256" } }, true, ["encrypt"]);
        }
        
        static async importPrivateKey() {
            var getData = await this.exportPrivateKey();
            return await window.crypto.subtle.importKey("jwk", getData, { name: "RSA-OAEP", hash: { name: "SHA-256" } }, true, ["decrypt"]);
        }
        
        static async generateKey() {
            return await window.crypto.subtle.generateKey({
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: { name: 'SHA-256' },
            }, true, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            );
        }
        
        static async encrypt(data) {
            var getData = await this.importPublicKey();
            return window.crypto.subtle.encrypt({
                name: "AES-GCM",
                iv: this.enc.encode(this.EncryptionIV),
                tagLength: 128, //can be 32, 64, 96, 104, 112, 120 or 128 (default)
            }, getData, //from generateKey or importKey above
            data //ArrayBuffer of data you want to encrypt
            );
        }
        
        static async decrypt(data) {
            var getData = await this.importPrivateKey();
            return window.crypto.subtle.decrypt({
                name: "AES-GCM",
                iv: this.enc.encode(this.EncryptionIV), //The initialization vector you used to encrypt
                tagLength: 128, //The tagLength you used to encrypt (if any)
            }, getData, //from generateKey or importKey above
            data //ArrayBuffer of the data
            );
        }
        
        static async encryptAndStore(key, data, storage = 'localStorage') {
            const encryptedData = await this.encrypt(new TextEncoder().encode(data));
            window[storage].setItem(key, JSON.stringify(Array.from(new Uint8Array(encryptedData))));
        }
        
        static async decryptFromStorage(key, storage = 'localStorage') {
            const encryptedData = JSON.parse(window[storage].getItem(key) || '[]');
            if (encryptedData.length === 0) return null;
            const encryptedArray = new Uint8Array(encryptedData);
            const decryptedData = await this.decrypt(encryptedArray);
            return new TextDecoder().decode(decryptedData);
        }
    }
    CryptoToolkit.CryptoUtils = CryptoUtils;
})(CryptoToolkit || (CryptoToolkit = {}));
