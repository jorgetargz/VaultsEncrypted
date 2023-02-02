package org.jorgetargz.client.domain.services.impl;

import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import jakarta.inject.Inject;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.client.dao.UsersDAO;
import org.jorgetargz.client.dao.VaultDAO;
import org.jorgetargz.client.domain.services.VaultServices;
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
import java.util.Base64;
import java.util.List;

@Log4j2
public class VaultServicesImpl implements VaultServices {

    private final VaultDAO vaultDAO;

    @Inject
    public VaultServicesImpl(VaultDAO vaultDAO, UsersDAO usersDAO) {
        this.vaultDAO = vaultDAO;
    }

    @Override
    public Single<Either<String, List<Vault>>> getAll() {
        return vaultDAO.getAll();
    }

    @Override
    public Single<Either<String, Vault>> get(String vaultName, String username, String password) {
        vaultName = Base64.getEncoder().encodeToString(vaultName.getBytes());
        username = Base64.getEncoder().encodeToString(username.getBytes());
        password = Base64.getEncoder().encodeToString(password.getBytes());
        return vaultDAO.get(vaultName, username, password);
    }

    @Override
    public Single<Either<String, Vault>> save(Vault vault, String userPass) {
        String vaultPassword = vault.getKey();

        //Se lee el keyStore para obtener el certificado
        Path keystorePath = Paths.get(vault.getUsernameOwner() + "KeyStore.pfx");
        if (!Files.exists(keystorePath)) {
            log.error("No existe el keystore");
            throw new RuntimeException("No existe el keystore");
        }
        char[] secretKey = userPass.toCharArray();
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

        String vaultPasswordEncryptedBase64 = Base64.getEncoder().encodeToString(vaultPasswordEncryptedBytes);

        vault.setKey(vaultPasswordEncryptedBase64);
        return vaultDAO.save(vault);
    }

    @Override
    public Single<Either<String, Boolean>> changePassword(Vault credentials, String password) {
        password = Base64.getEncoder().encodeToString(password.getBytes());
        return vaultDAO.changePassword(credentials, password);
    }

    @Override
    public Single<Either<String, Boolean>> delete(int vaultId) {
        return vaultDAO.delete(vaultId);
    }
}
