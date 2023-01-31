package org.jorgetargz.server.jakarta.security;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import lombok.extern.log4j.Log4j2;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Log4j2
public class RSAKeyPairProducer {

    @Produces
    @Singleton
    public KeyPair getRsaKeyPair() {
        Path privateKeyPath = Paths.get("privateKey");
        Path publicKeyPath = Paths.get("publicKey");
        KeyPair keyPair;

        if (privateKeyPath.toFile().exists() && publicKeyPath.toFile().exists()) {
            keyPair = readKeyPair(privateKeyPath, publicKeyPath);
        } else {
            keyPair = createKeyPair(privateKeyPath, publicKeyPath);
        }
        return keyPair;
    }

    private KeyPair readKeyPair(Path privateKeyPath, Path publicKeyPath) {
        KeyPair keyPair;
        try {
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyPath);
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyPath);

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            keyPair = new KeyPair(publicKey, privateKey);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al leer las claves RSA");
        }
        return keyPair;
    }

    private static KeyPair createKeyPair(Path privateKeyPath, Path publicKeyPath) {
        KeyPair keyPair;
        KeyPairGenerator generadorRSA4096;
        try {
            generadorRSA4096 = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
        generadorRSA4096.initialize(2048);
        keyPair = generadorRSA4096.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());

        try {
            Files.write(privateKeyPath, privateKeySpec.getEncoded());
            Files.write(publicKeyPath, publicKeySpec.getEncoded());
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al guardar las claves RSA");
        }
        return keyPair;
    }
}