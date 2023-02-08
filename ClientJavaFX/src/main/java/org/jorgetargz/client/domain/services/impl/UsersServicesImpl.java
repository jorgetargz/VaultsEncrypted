package org.jorgetargz.client.domain.services.impl;

import com.nimbusds.jose.util.X509CertUtils;
import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.RandomStringUtils;
import org.jorgetargz.client.dao.UsersDAO;
import org.jorgetargz.client.domain.services.UsersServices;
import org.jorgetargz.security.EncriptacionAES;
import org.jorgetargz.security.EncriptacionRSA;
import org.jorgetargz.security.KeyPairUtils;
import org.jorgetargz.security.KeyStoreUtils;
import org.jorgetargz.utils.common.ConstantesAPI;
import org.jorgetargz.utils.modelo.ContentCiphedAES;
import org.jorgetargz.utils.modelo.User;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

@Log4j2
public class UsersServicesImpl implements UsersServices {

    private final UsersDAO usersDAO;
    private final PublicKey serverPublicKey;
    private final EncriptacionAES encriptacionAES;
    private final EncriptacionRSA encriptacionRSA;
    private final KeyStoreUtils keyStoreUtils;
    private final KeyPairUtils keyPairUtils;

    @Inject
    public UsersServicesImpl(@Named("serverPublicKey") PublicKey serverPublicKey,
                             UsersDAO usersDAO, EncriptacionAES encriptacionAES, EncriptacionRSA encriptacionRSA, KeyStoreUtils keyStoreUtils, KeyPairUtils keyPairUtils) {
        this.usersDAO = usersDAO;
        this.serverPublicKey = serverPublicKey;
        this.encriptacionAES = encriptacionAES;
        this.encriptacionRSA = encriptacionRSA;
        this.keyStoreUtils = keyStoreUtils;
        this.keyPairUtils = keyPairUtils;
    }

    @Override
    public Single<Either<String, User>> save(User user) {

        //Se establece el rol del usuario
        user.setRole(ConstantesAPI.ROLE_USER);

        //Se genera una clave simétrica AES de 256 bits
        KeyPair clavesRSACliente;
        try {
            clavesRSACliente = keyPairUtils.generateKeyPair(2048);
        } catch (NoSuchAlgorithmException e) {
            return Single.just(Either.left("Error al generar las claves RSA"));
        }
        PrivateKey clavePrivadaCliente = clavesRSACliente.getPrivate();
        PublicKey clavePublicaCliente = clavesRSACliente.getPublic();

        //Se obtiene la clave pública del cliente en formato X509EncodedKeySpec
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(clavePublicaCliente.getEncoded());

        //Generar una clave aleatoria
        String password = RandomStringUtils.randomAlphanumeric(16);

        //Se obtiene la clave pública del cliente en formato Base64
        String clavePublicaClienteBase64 = Base64.getUrlEncoder().encodeToString(x509Spec.getEncoded());

        // Se encripta con AES la clave pública con la clave aleatoria
        ContentCiphedAES clavePublicaClienteEncriptada = encriptacionAES.encriptar(clavePublicaClienteBase64, password);

        // Se almacena la clave pública encriptada en el usuario
        user.setPublicKeyEncrypted(clavePublicaClienteEncriptada);

        //Se encripta la clave aleatoria con la clave pública del servidor
        byte[] passwordEncrypted;
        try {
            passwordEncrypted = encriptacionRSA.encriptar(password.getBytes(), serverPublicKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left("Error al encriptar la clave aleatoria"));
        }

        //Se almacena la clave aleatoria encriptada en el usuario codificada en Base64
        user.setEncryptedPasswordOfPublicKeyEncrypted(Base64.getUrlEncoder().encodeToString(passwordEncrypted));

        // Se almacena el usuario en la base de datos y se obtiene el
        // usuario con un certificado firmado por el servidor
        CompletableFuture<User> userCompletableFuture = new CompletableFuture<>();
        User userWithCertificate;
        try {
            usersDAO.save(user)
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
            userWithCertificate = userCompletableFuture.join();
        } catch (RuntimeException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left("Error al guardar el usuario en la base de datos"));
        }

        // Se obtiene el certificado del usuario
        X509Certificate cert = X509CertUtils.parse(Base64.getUrlDecoder().decode(userWithCertificate.getCertificate()));

        //Se crea un KeyStore
        KeyStore ks;
        try {
            ks = keyStoreUtils.createKeyStore(user.getPassword(), cert, clavePrivadaCliente);
        } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException e) {
            return Single.just(Either.left("Error al crear el KeyStore"));
        }

        // Se guarda el KeyStore en un fichero
        Path keystorePath = Paths.get(user.getUsername() + "KeyStore.pfx");
        try (OutputStream fos = Files.newOutputStream(keystorePath)) {
            ks.store(fos, user.getPassword().toCharArray());
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            log.error(e.getMessage(), e);
            return Single.just(Either.left("Error al guardar el KeyStore"));
        }

        return Single.just(Either.right(userWithCertificate));
    }

    @Override
    public Single<Either<String, Boolean>> delete(String username) {
        Path keystorePath = Paths.get(username + "KeyStore.pfx");
        try {
            Files.delete(keystorePath);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
        username = Base64.getUrlEncoder().encodeToString(username.getBytes());
        return usersDAO.delete(username);
    }
}
