package com.spring.security.security;

import java.util.Base64;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CryptoServiceImpl implements CryptoService {
    @Autowired
    private AESCryptoService aesCryptoService;

    @Autowired
    private RSACryptoService rsaCryptoService;

    private SecretKey aesKey;
    private byte[] aesIv;

    @PostConstruct
    public void init() throws Exception {
        aesKey = aesCryptoService.generateKey();
        aesIv = aesCryptoService.generateIv();
    }

    @Override
    public String encryptAES(String data) throws Exception {
        return aesCryptoService.encrypt(data, aesKey, aesIv);
    }

    @Override
    public String decryptAES(String encryptedData) throws Exception {
        return aesCryptoService.decrypt(encryptedData, aesKey, aesIv);
    }

    @Override
    public String encryptRSA(String data) throws Exception {
        return rsaCryptoService.encrypt(data);
    }

    @Override
    public String decryptRSA(String encryptedData) throws Exception {
        return rsaCryptoService.decrypt(encryptedData);
    }

    @Override
    public String hybridEncrypt(String data) throws Exception {
        // Encrypt data with AES key
        SecretKey aesKey = aesCryptoService.generateKey();
        byte[] aesIv = aesCryptoService.generateIv();
        String encryptedData = aesCryptoService.encrypt(data, aesKey, aesIv);

        // Encrypt AES key with RSA public key
        String aesKeyStr = Base64.getEncoder().encodeToString(aesKey.getEncoded());
        String encryptedAesKey = rsaCryptoService.encrypt(aesKeyStr);

        // Return concatenated encrypted AES key and encrypted data
        return encryptedAesKey + ":" + encryptedData;
    }

    /**
     * Decrypts the given hybrid encrypted data.
     *
     * @param encryptedData the encrypted data to be decrypted
     * @return the decrypted data
     * @throws Exception if an error occurs during decryption
     */
    @Override
    public String hybridDecrypt(String encryptedData) throws Exception {
        // Split encrypted AES key and encrypted data
        String[] parts = encryptedData.split(":");
        String encryptedAesKey = parts[0];
        String encryptedMessage = parts[1];

        // Decrypt AES key with RSA private key
        String decryptedAesKeyStr = rsaCryptoService.decrypt(encryptedAesKey);
        byte[] decodedKey = Base64.getDecoder().decode(decryptedAesKeyStr);
        SecretKey aesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        // Decrypt data with decrypted AES key
        return aesCryptoService.decrypt(encryptedMessage, aesKey, aesIv);
    }

    @Override
    public Map<String, Object> generateRSAKeypair() throws Exception {
        return rsaCryptoService.generateKeyPair();
    }

}
