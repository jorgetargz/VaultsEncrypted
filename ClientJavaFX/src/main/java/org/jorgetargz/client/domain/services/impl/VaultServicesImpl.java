package org.jorgetargz.client.domain.services.impl;

import com.nimbusds.jose.util.X509CertUtils;
import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import jakarta.inject.Inject;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.client.dao.UsersDAO;
import org.jorgetargz.client.dao.VaultDAO;
import org.jorgetargz.client.dao.vault_api.utils.CacheAuthorization;
import org.jorgetargz.client.domain.common.Constantes;
import org.jorgetargz.client.domain.services.VaultServices;
import org.jorgetargz.security.EncriptacionRSA;
import org.jorgetargz.security.KeyStoreUtils;
import org.jorgetargz.utils.modelo.User;
import org.jorgetargz.utils.modelo.Vault;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@Log4j2
public class VaultServicesImpl implements VaultServices {

    private final VaultDAO vaultDAO;
    private final UsersDAO usersDAO;
    private final CacheAuthorization cacheAuthorization;
    private final KeyStoreUtils keyStoreUtils;
    private final EncriptacionRSA encriptacionRSA;

    @Inject
    public VaultServicesImpl(VaultDAO vaultDAO, UsersDAO usersDAO, CacheAuthorization cacheAuthorization, KeyStoreUtils keyStoreUtils, EncriptacionRSA encriptacionRSA) {
        this.vaultDAO = vaultDAO;
        this.usersDAO = usersDAO;
        this.cacheAuthorization = cacheAuthorization;
        this.keyStoreUtils = keyStoreUtils;
        this.encriptacionRSA = encriptacionRSA;
    }

    @Override
    public Single<Either<String, List<Vault>>> getAll() {
        return vaultDAO.getAll();
    }

    @Override
    public Single<Either<String, Vault>> get(String vaultName, String username, String vaultPassword) {
        vaultName = Base64.getUrlEncoder().encodeToString(vaultName.getBytes());
        username = Base64.getUrlEncoder().encodeToString(username.getBytes());

        CompletableFuture<Vault> vaultCompletableFuture = new CompletableFuture<>();
        Vault vault;
        try {
            vaultDAO.get(vaultName, username)
                    .subscribe(either -> {
                        if (either.isLeft()) {
                            log.error(either.getLeft());
                            vaultCompletableFuture.completeExceptionally(new RuntimeException(either.getLeft()));
                        } else {
                            vaultCompletableFuture.complete(either.get());
                        }
                    });
            vault = vaultCompletableFuture.join();
        } catch (RuntimeException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left(e.getMessage()));
        }

        //Se lee el keyStore del usuario
        KeyStore keyStore;
        try {
            keyStore = getKeyStore();
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left(Constantes.ERROR_READING_KEYSTORE));
        }

        //Se obtiene la clave privada
        PrivateKey privateKey;
        try {
            privateKey = keyStoreUtils.getPrivateKey(keyStore, Constantes.PRIVADA_ALIAS, cacheAuthorization.getPassword());
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left(Constantes.ERROR_READING_PRIVATE_KEY));
        }

        //Se decodifica la clave pública encriptada con Base64
        byte[] passwordEncrypted = Base64.getUrlDecoder().decode(vault.getKey());

        //Se desencripta la contraseña con la clave privada del usuario
        byte[] passwordDecryptedBytes;
        try {
            passwordDecryptedBytes = encriptacionRSA.desencriptar(passwordEncrypted, privateKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left(Constantes.ERROR_DECRYPTING_PASSWORD));
        }

        String passwordDecrypted = new String(passwordDecryptedBytes);
        if (passwordDecrypted.equals(vaultPassword)) {
            vault.setKey(vaultPassword);
            return Single.just(Either.right(vault));
        } else {
            log.error(Constantes.WRONG_PASSWORD);
            return Single.just(Either.left(Constantes.WRONG_PASSWORD));
        }
    }

    @Override
    public Single<Either<String, Vault>> save(Vault vault) {
        String vaultPassword = vault.getKey();

        //Se lee el keyStore del usuario
        KeyStore keyStore;
        try {
            keyStore = getKeyStore();
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left(Constantes.ERROR_READING_KEYSTORE));
        }


        //Se obtiene la clave pública del certificado
        PublicKey publicKey;
        try {
            publicKey = keyStoreUtils.getPublicKey(keyStore, Constantes.PUBLICA_ALIAS);
        } catch (KeyStoreException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left(Constantes.ERROR_AL_OBTENER_LA_CLAVE_PUB_DEL_CERT));
        }

        //Se cifra la contraseña del vault con la clave pública
        byte[] vaultPasswordEncryptedBytes;
        try {
            vaultPasswordEncryptedBytes = encriptacionRSA.encriptar(vaultPassword.getBytes(), publicKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left(Constantes.ERROR_AL_CIFRAR_LA_CLAVE_DEL_VAULT));
        }

        String vaultPasswordEncryptedBase64 = Base64.getUrlEncoder().encodeToString(vaultPasswordEncryptedBytes);

        vault.setKey(vaultPasswordEncryptedBase64);
        return vaultDAO.save(vault);
    }

    @Override
    public Single<Either<String, Vault>> share(Vault vault, String username) {
        CompletableFuture<User> userCompletableFuture = new CompletableFuture<>();
        String usernameBase64 = Base64.getUrlEncoder().encodeToString(username.getBytes());
        User user;
        try {
            usersDAO.get(usernameBase64)
                    .subscribe(either -> {
                        if (either.isLeft()) {
                            userCompletableFuture.completeExceptionally(
                                    new RuntimeException(either.getLeft())
                            );
                            log.error(either.getLeft());
                        } else {
                            userCompletableFuture.complete(either.get());
                        }
                    });
            user = userCompletableFuture.join();
        } catch (RuntimeException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left(Constantes.ERROR_GETTING_USER));
        }
        String certificateBase64 = user.getCertificate();

        X509Certificate certificate = X509CertUtils.parse(Base64.getUrlDecoder().decode(certificateBase64));

        //Se obtiene la clave pública del certificado
        PublicKey publicKey = certificate.getPublicKey();

        //Se cifra la contraseña del vault con la clave pública del usuario a compartir
        byte[] vaultPasswordEncryptedBytes;
        try {
            vaultPasswordEncryptedBytes = encriptacionRSA.encriptar(vault.getKey().getBytes(), publicKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left(Constantes.ERROR_AL_ENCRIPTAR_LA_CLAVE_DEL_VAULT_CON_LA_CLAVE_PUBLICA_DEL_USUARIO_A_COMPARTIR));
        }

        //Se codifica la clave encriptada con Base64
        String passwordEncWithUserPubKeyBase64 = Base64.getUrlEncoder().encodeToString(vaultPasswordEncryptedBytes);

        return vaultDAO.share(vault, usernameBase64, passwordEncWithUserPubKeyBase64);
    }

    @Override
    public Single<Either<String, Boolean>> delete(int vaultId) {
        return vaultDAO.delete(vaultId);
    }

    private KeyStore getKeyStore() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        Path keystorePath = Paths.get(cacheAuthorization.getUser() + Constantes.KEY_STORE_PFX);
        KeyStore keyStore;
        keyStore = keyStoreUtils.getKeyStore(keystorePath, cacheAuthorization.getPassword());
        return keyStore;
    }
}
