package com.spring.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring.security.security.CryptoService;

@RestController
@RequestMapping("/crypto")
public class CryptoController {
    @Autowired
    private CryptoService cryptoService;

    @PostMapping("/encrypt/aes")
    public String encryptAES(@RequestBody String data) throws Exception {
        return cryptoService.encryptAES(data);
    }

    @PostMapping("/decrypt/aes")
    public String decryptAES(@RequestBody String encryptedData) throws Exception {
        return cryptoService.decryptAES(encryptedData);
    }

    @PostMapping("/encrypt/rsa")
    public String encryptRSA(@RequestBody String data) throws Exception {
        return cryptoService.encryptRSA(data);
    }

    @PostMapping("/decrypt/rsa")
    public String decryptRSA(@RequestBody String encryptedData) throws Exception {
        return cryptoService.decryptRSA(encryptedData);
    }

    @PostMapping("/encrypt/hybrid")
    public String hybridEncrypt(@RequestBody String data) throws Exception {
        return cryptoService.hybridEncrypt(data);
    }

    @PostMapping("/decrypt/hybrid")
    public String hybridDecrypt(@RequestBody String encryptedData) throws Exception {
        return cryptoService.hybridDecrypt(encryptedData);
    }
}
