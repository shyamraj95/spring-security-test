package com.spring.security.security;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class RSACryptoService {
    private static final String RSA = "RSA";
    private static final int KEY_SIZE = 2048;

    // @Value("${RSA_PRIVATE_KEY_PATH}")
    private String privateKeyPath = "F:/spring-boot-workspaces/private_key.pem";

    // @Value("${RSA_PUBLIC_KEY_PATH}")
    private String publicKeyPath = "F:/spring-boot-workspaces/public_key.pem";

    private PublicKey rsaPublicKey;
    private PrivateKey rsaPrivateKey;

    @PostConstruct
    public void init() throws Exception {
        generateKeyPair();
/*         rsaPublicKey = loadPublicKey(publicKeyPath);
        rsaPrivateKey = loadPrivateKey(privateKeyPath); */
    }

    private PublicKey loadPublicKey(String path) throws Exception {
        /*
         * byte[] keyBytes = Files.readAllBytes(Paths.get(path));
         * X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
         * KeyFactory kf = KeyFactory.getInstance(RSA);
         * return kf.generatePublic(spec);
         */
        String publicKeyPEM = new String(Files.readAllBytes(Paths.get(path)));
       // System.out.println(publicKeyPEM);
        publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "")
                                  .replace("-----END PUBLIC KEY-----", "")
                                  .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private PrivateKey loadPrivateKey(String path) throws Exception {
/*         byte[] keyBytes = Files.readAllBytes(Paths.get(path));
        System.out.println(keyBytes);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePrivate(spec); */
        String privateKeyPEM = new String(Files.readAllBytes(Paths.get(path)));
      //  System.out.println(privateKeyPEM);
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "")
                                    .replace("-----END PRIVATE KEY-----", "")
                                    .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }

    public Map<String, Object> generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(KEY_SIZE);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println(publicKey);
        System.out.println(privateKey);
        /* saveKeyPair(keyPair); */
        Map<String, Object> keyPairMap = new HashMap<>();
        keyPairMap.put("privateKey", privateKey.getEncoded());
        keyPairMap.put("publicKey", publicKey.getEncoded());
       
        return keyPairMap;
    }

    /*
     * private static void saveKeyPair(KeyPair keyPair) throws IOException {
     * PublicKey publicKey = keyPair.getPublic();
     * PrivateKey privateKey = keyPair.getPrivate();
     * 
     * saveKeyToFile("public_key.pem", "PUBLIC KEY", publicKey.getEncoded());
     * saveKeyToFile("private_key.pem", "PRIVATE KEY", privateKey.getEncoded());
     * }
     * 
     * private static void saveKeyToFile(String filename, String description, byte[]
     * key) throws IOException {
     * PemObject pemObject = new PemObject(description, key);
     * try (PemWriter pemWriter = new PemWriter(new FileOutputStream(filename))) {
     * pemWriter.writeObject(pemObject);
     * }
     * }
     */
}
