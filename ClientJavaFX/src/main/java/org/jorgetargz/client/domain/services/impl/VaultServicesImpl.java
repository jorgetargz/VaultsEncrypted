package org.jorgetargz.client.domain.services.impl;

import com.nimbusds.jose.util.X509CertUtils;
import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import jakarta.inject.Inject;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.client.dao.UsersDAO;
import org.jorgetargz.client.dao.VaultDAO;
import org.jorgetargz.client.dao.vault_api.utils.CacheAuthorization;
import org.jorgetargz.client.domain.services.VaultServices;
import org.jorgetargz.utils.modelo.User;
import org.jorgetargz.utils.modelo.Vault;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
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

    @Inject
    public VaultServicesImpl(VaultDAO vaultDAO, UsersDAO usersDAO, CacheAuthorization cacheAuthorization) {
        this.vaultDAO = vaultDAO;
        this.usersDAO = usersDAO;
        this.cacheAuthorization = cacheAuthorization;
    }

    @Override
    public Single<Either<String, List<Vault>>> getAll() {
        return vaultDAO.getAll();
    }

    @Override
    public Vault get(String vaultName, String username, String vaultPassword) {
        vaultName = Base64.getUrlEncoder().encodeToString(vaultName.getBytes());
        username = Base64.getUrlEncoder().encodeToString(username.getBytes());

        CompletableFuture<Vault> vaultCompletableFuture = new CompletableFuture<>();
        vaultDAO.get(vaultName, username)
                .subscribe(either -> {
                    if (either.isLeft()) {
                        vaultCompletableFuture.completeExceptionally(
                                new RuntimeException(either.getLeft())
                        );
                        log.error(either.getLeft());
                    } else {
                        vaultCompletableFuture.complete(either.get());
                    }
                });
        Vault vault = vaultCompletableFuture.join();
        //Se lee el keyStore para obtener el certificado
        Path keystorePath = Paths.get(cacheAuthorization.getUser() + "KeyStore.pfx");
        if (!Files.exists(keystorePath)) {
            log.error("No existe el keystore");
            throw new RuntimeException("No existe el keystore");
        }
        char[] secretKey = cacheAuthorization.getPassword().toCharArray();
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al obtener el KeyStore");
        }
        try {
            keyStore.load(Files.newInputStream(keystorePath), secretKey);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al cargar el KeyStore");
        }

        //Se obtiene la clave privada
        PrivateKey privateKey;
        try {
            privateKey = (PrivateKey) keyStore.getKey("privada", secretKey);
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        //Se decodifica la clave pública encriptada con Base64
        byte[] passwordEncrypted = Base64.getUrlDecoder().decode(vault.getKey());

        //Se desencripta la contraseña con la clave privada del usuario
        byte[] passwordDecryptedBytes;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            passwordDecryptedBytes = cipher.doFinal(passwordEncrypted);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }

        String passwordDecrypted = new String(passwordDecryptedBytes);
        if (passwordDecrypted.equals(vaultPassword)) {
            vault.setKey(vaultPassword);
            return vault;
        } else {
            log.error("Wrong password");
            throw new RuntimeException("Wrong password");
        }
    }

    @Override
    public Single<Either<String, Vault>> save(Vault vault) {
        String vaultPassword = vault.getKey();

        //Se lee el keyStore para obtener el certificado
        Path keystorePath = Paths.get(cacheAuthorization.getUser() + "KeyStore.pfx");
        if (!Files.exists(keystorePath)) {
            log.error("No existe el keystore");
            throw new RuntimeException("No existe el keystore");
        }
        char[] secretKey = cacheAuthorization.getPassword().toCharArray();
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al obtener el KeyStore");
        }
        try {
            keyStore.load(Files.newInputStream(keystorePath), secretKey);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al cargar el KeyStore");
        }

        //Se obtiene la clave pública del certificado
        PublicKey publicKey;
        try {
            publicKey = keyStore.getCertificate("publica").getPublicKey();
        } catch (KeyStoreException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al obtener la clave publica del certificado");
        }

        //Se cifra la contraseña del vault con la clave pública
        byte[] vaultPasswordEncryptedBytes;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            vaultPasswordEncryptedBytes = cipher.doFinal(vaultPassword.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al encriptar la clave del vault con la clave privada");
        }

        String vaultPasswordEncryptedBase64 = Base64.getUrlEncoder().encodeToString(vaultPasswordEncryptedBytes);

        vault.setKey(vaultPasswordEncryptedBase64);
        return vaultDAO.save(vault);
    }

    @Override
    public Single<Either<String, Vault>> share(Vault vault, String username) {
        CompletableFuture<User> userCompletableFuture = new CompletableFuture<>();
        String usernameBase64 = Base64.getUrlEncoder().encodeToString(username.getBytes());
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
        User user = userCompletableFuture.join();
        String certificateBase64 = user.getCertificate();

        X509Certificate certificate = X509CertUtils.parse(Base64.getUrlDecoder().decode(certificateBase64));

        //Se obtiene la clave pública del certificado
        PublicKey publicKey = certificate.getPublicKey();

        //Se cifra la contraseña del vault con la clave pública
        byte[] vaultPasswordEncryptedBytes;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            vaultPasswordEncryptedBytes = cipher.doFinal(vault.getKey().getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al encriptar la clave del vault con la clave publica del usuario");
        }

        //Se codifica la clave encriptada con Base64
        String passwordEncWithUserPubKeyBase64 = Base64.getUrlEncoder().encodeToString(vaultPasswordEncryptedBytes);

        return vaultDAO.share(vault, usernameBase64, passwordEncWithUserPubKeyBase64);
    }

    @Override
    public Single<Either<String, Boolean>> delete(int vaultId) {
        return vaultDAO.delete(vaultId);
    }
}
