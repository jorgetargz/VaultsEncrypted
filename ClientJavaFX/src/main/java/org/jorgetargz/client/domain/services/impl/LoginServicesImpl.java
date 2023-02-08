package org.jorgetargz.client.domain.services.impl;

import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import jakarta.inject.Inject;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.RandomStringUtils;
import org.jorgetargz.client.dao.LoginDAO;
import org.jorgetargz.client.dao.vault_api.utils.CacheAuthorization;
import org.jorgetargz.client.domain.common.Constantes;
import org.jorgetargz.client.domain.services.LoginServices;
import org.jorgetargz.security.KeyStoreUtils;
import org.jorgetargz.utils.modelo.User;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;

@Log4j2
public class LoginServicesImpl implements LoginServices {

    private final LoginDAO loginDAO;
    private final CacheAuthorization cache;
    private final KeyStoreUtils keyStoreUtils;

    @Inject
    public LoginServicesImpl(LoginDAO loginDAO, CacheAuthorization cache, KeyStoreUtils keyStoreUtils) {
        this.loginDAO = loginDAO;
        this.cache = cache;
        this.keyStoreUtils = keyStoreUtils;
    }

    @Override
    public Single<Either<String, User>> scLogin(String username, String password) {
        //Se comprueba si el usuario tiene un KeyStore
        Path keystorePath = Paths.get(username + Constantes.KEY_STORE_PFX);
        if (!Files.exists(keystorePath)) {
            log.error(Constantes.NO_EXISTE_EL_KEYSTORE);
            return Single.just(Either.left(Constantes.NO_EXISTE_EL_KEYSTORE));
        }

        //Se lee el keyStore del usuario
        KeyStore keyStore;
        try {
            keyStore = keyStoreUtils.getKeyStore(keystorePath, password);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left(Constantes.ERROR_AL_LEER_EL_KEY_STORE));
        }

        //Se obtiene la clave privada del KeyStore
        PrivateKey privateKey;
        try {
            privateKey = keyStoreUtils.getPrivateKey(keyStore, Constantes.PRIVADA_ALIAS, password);
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left(Constantes.ERROR_AL_OBTENER_LA_CLAVE_PRIVADA_DEL_KEY_STORE));
        }

        //Se genera un String aleatorio
        String randomString = RandomStringUtils.randomAlphanumeric(20);

        //Se firma el String aleatorio
        byte[] signature;
        try {
            Signature sign = Signature.getInstance(Constantes.SHA_256_WITH_RSA);
            sign.initSign(privateKey);
            sign.update(randomString.getBytes());
            signature = sign.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left(Constantes.ERROR_AL_FIRMAR_EL_STRING_ALEATORIO));
        }

        //Se codifica en Base64
        String usernameBase64 = Base64.getUrlEncoder().encodeToString(username.getBytes());
        String signatureBase64 = Base64.getUrlEncoder().encodeToString(signature);
        String randomStringBase64 = Base64.getUrlEncoder().encodeToString(randomString.getBytes());

        //Se envía el String aleatorio y la firma codificada en base64 al servidor
        //para que valide la firma y devuelva el token
        String authorization = Constantes.CERTIFICATE +
                usernameBase64 +
                Constantes.SEPARATOR +
                randomStringBase64 +
                Constantes.SEPARATOR +
                signatureBase64;
        cache.setCertificateAuth(authorization);
        return loginDAO.login(authorization);
    }

    @Override
    public Single<Either<String, Boolean>> scLogout() {
        String jwtAuth = cache.getJwtAuth();
        cache.setUser(null);
        cache.setPassword(null);
        cache.setJwtAuth(null);
        cache.setCertificateAuth(null);
        return loginDAO.logout(jwtAuth);
    }
}
