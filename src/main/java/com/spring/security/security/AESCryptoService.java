package com.spring.security.security;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.springframework.stereotype.Service;

import com.spring.security.exception.CryptoException;
@Service
public class AESCryptoService {
    private static final String AES = "AES";
    private static final String AES_CBC = "AES/CBC/PKCS5PADDING";

    // Encrypt data using AES in CBC mode
    public String encrypt(String data, SecretKey secretKey, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(AES_CBC);
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new CryptoException("Failed to encrypt data using AES", e);
        }
    }

    // Decrypt data using AES in CBC mode
    public String decrypt(String encryptedData, SecretKey secretKey, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(AES_CBC);
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(original);
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt data using AES", e);
        }
    }

    // Generate a new AES key
    public SecretKey generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES);
            keyGen.init(256); // Example: 256-bit AES
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new CryptoException("Failed to generate AES key", e);
        }
    }

    // Generate a new Initialization Vector (IV) for AES
    public byte[] generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
