package com.spring.security.security;

import java.util.Map;

public interface CryptoService {
    String encryptAES(String data) throws Exception;

    String decryptAES(String encryptedData) throws Exception;

    String encryptRSA(String data) throws Exception;

    String decryptRSA(String encryptedData) throws Exception;

    String hybridEncrypt(String data) throws Exception;

    String hybridDecrypt(String encryptedData) throws Exception;

    Map<String, Object> generateRSAKeypair() throws Exception;
}
