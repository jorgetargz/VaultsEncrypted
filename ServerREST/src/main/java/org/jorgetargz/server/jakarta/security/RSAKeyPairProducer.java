package org.jorgetargz.server.jakarta.security;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import lombok.extern.log4j.Log4j2;
import org.bouncycastle.operator.OperatorCreationException;
import org.jorgetargz.security.KeyPairUtils;
import org.jorgetargz.security.KeyStoreUtils;
import org.jorgetargz.server.jakarta.common.Constantes;

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
        Path keystorePath = Paths.get(Constantes.PATH_SERVER_KEYSTORE);
        String keystorePassword = Constantes.SERVER_SECRET_KEY;

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
            throw new RuntimeException(Constantes.ERROR_AL_CARGAR_EL_KEY_STORE);
        }

        //Se obtiene la clave pública
        PublicKey publicKey;
        try {
            publicKey = keyStoreUtils.getPublicKey(keyStore, Constantes.PUBLICA);
        } catch (KeyStoreException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(Constantes.ERROR_AL_OBTENER_LA_CLAVE_PUBLICA_DEL_CERTIFICADO);
        }

        //Se obtiene la clave privada del keyStore
        PrivateKey privateKey;
        try {
            privateKey = keyStoreUtils.getPrivateKey(keyStore, Constantes.PRIVADA, keystorePassword);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(Constantes.ERROR_AL_OBTENER_LA_CLAVE_PRIVADA_DEL_KEY_STORE);
        }

        return new KeyPair(publicKey, privateKey);
    }

    private KeyPair createKeyPair(String keystorePassword, Path keystorePath, KeyStoreUtils keyStoreUtils, KeyPairUtils keyPairUtils) {
        //Se genera el par de claves
        KeyPair keyPair;
        try {
            keyPair = keyPairUtils.generateKeyPair(Constantes.KEY_SIZE);
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        //Se crea el KeyStore
        KeyStore keyStore;
        try {
            keyStore = keyStoreUtils.createKeyStoreWithAutoSignedCert(keystorePassword, Constantes.SERVER, publicKey, privateKey);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException |
                 OperatorCreationException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(Constantes.ERROR_AL_CREAR_EL_KEY_STORE);
        }

        // Se guarda el KeyStore en un fichero
        try (OutputStream fos = Files.newOutputStream(keystorePath)) {
            //Se guarda el KeyStore en el fichero
            keyStore.store(fos, keystorePassword.toCharArray());
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(Constantes.NO_SE_HA_PODIDO_GUARDAR_EL_KEY_STORE_EN_EL_FICHERO);
        }
        return keyPair;
    }
}