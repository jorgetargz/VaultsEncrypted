package org.jorgetargz.server.jakarta.security;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import lombok.extern.log4j.Log4j2;
import org.bouncycastle.operator.OperatorCreationException;
import org.jorgetargz.security.KeyPairUtils;
import org.jorgetargz.security.KeyStoreUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;

@Log4j2
public class RSAKeyPairProducer {

    @Produces
    @Singleton
    public KeyPair getRsaKeyPair(KeyStoreUtils keyStoreUtils, KeyPairUtils keyPairUtils) {
        Path keystorePath = Paths.get("/opt/payara/appserver/glassfish/domains/domain1/applications/ServerRest-1.0-SNAPSHOT/WEB-INF/classes/keys/keystore.pfx");
        String keystorePassword = "serverSecretKey";

        KeyPair keyPair;
        if (keystorePath.toFile().exists()) {
            keyPair = readKeyPair(keystorePassword, keystorePath, keyStoreUtils);
        } else {
            keyPair = createKeyPair(keystorePassword, keystorePath, keyStoreUtils, keyPairUtils);
        }
        return keyPair;
    }

    private KeyPair readKeyPair(String keystorePassword, Path keystorePath, KeyStoreUtils keyStoreUtils) {
        //Se lee el keyStore
        KeyStore keyStore;
        try {
            keyStore = keyStoreUtils.getKeyStore(keystorePath, keystorePassword);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al cargar el KeyStore");
        }

        //Se obtiene la clave pública
        PublicKey publicKey;
        try {
            publicKey = keyStoreUtils.getPublicKey(keyStore, "publica");
        } catch (KeyStoreException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al obtener la clave publica del certificado");
        }

        //Se obtiene la clave privada del keyStore
        PrivateKey privateKey;
        try {
            privateKey = keyStoreUtils.getPrivateKey(keyStore, "privada", keystorePassword);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al obtener la clave privada del KeyStore");
        }

        return new KeyPair(publicKey, privateKey);
    }

    private KeyPair createKeyPair(String keystorePassword, Path keystorePath, KeyStoreUtils keyStoreUtils, KeyPairUtils keyPairUtils) {
        //Se genera el par de claves
        KeyPair keyPair;
        try {
            keyPair = keyPairUtils.generateKeyPair(2048);
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        //Se crea el KeyStore
        KeyStore keyStore;
        try {
            keyStore = keyStoreUtils.createKeyStoreWithAutoSignedCert(keystorePassword, "SERVER", publicKey, privateKey);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                 OperatorCreationException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al crear el KeyStore");
        }

        // Se guarda el KeyStore en un fichero
        try (OutputStream fos = Files.newOutputStream(keystorePath)) {
            //Se guarda el KeyStore en el fichero
            keyStore.store(fos, keystorePassword.toCharArray());
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("No se ha podido guardar el KeyStore en el fichero");
        }
        return keyPair;
    }
}