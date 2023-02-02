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
import org.jorgetargz.utils.common.ConstantesAPI;
import org.jorgetargz.utils.modelo.ContentCiphedAES;
import org.jorgetargz.utils.modelo.User;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
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

    @Inject
    public UsersServicesImpl(@Named("serverPublicKey") PublicKey serverPublicKey,
                             UsersDAO usersDAO, EncriptacionAES encriptacionAES) {
        this.usersDAO = usersDAO;
        this.serverPublicKey = serverPublicKey;
        this.encriptacionAES = encriptacionAES;
    }

    @Override
    public void save(User user) {

        //Se establece el rol del usuario
        user.setRole(ConstantesAPI.ROLE_USER);

        //Se genera una clave simétrica AES de 256 bits
        KeyPairGenerator generadorRSA;
        try {
            generadorRSA = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al generar la clave pública del cliente");
        }
        generadorRSA.initialize(2048);
        KeyPair clavesRSACliente = generadorRSA.generateKeyPair();
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
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            passwordEncrypted = cipher.doFinal(password.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("Error al encriptar la clave aleatoria con la clave pública del servidor");
        }

        //Se almacena la clave aleatoria encriptada en el usuario codificada en Base64
        user.setEncryptedPasswordOfPublicKeyEncrypted(Base64.getUrlEncoder().encodeToString(passwordEncrypted));

        // Se almacena el usuario en la base de datos y se obtiene el
        // usuario con un certificado firmado por el servidor
        CompletableFuture<User> userCompletableFuture = new CompletableFuture<>();
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
        User userWithCertificate = userCompletableFuture.join();

        //Se crea un KeyStore
        KeyStore ks;
        try {
            ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("No se ha podido crear el KeyStore");
        }

        // Se genera un salt aleatorio
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        // Se convierte el password en un char[] para poder usarla en el KeyStore
        char[] secretKey = user.getPassword().toCharArray();

        // Se obtiene el certificado del usuario
        X509Certificate cert = X509CertUtils.parse(Base64.getUrlDecoder().decode(userWithCertificate.getCertificate()));

        try {
            //Se guarda el certificado en el KeyStore
            ks.setCertificateEntry("publica", cert);
            //Se guarda la clave privada en el KeyStore con la misma secretKey que el KeyStore
            ks.setKeyEntry("privada", clavePrivadaCliente, secretKey, new Certificate[]{cert});
        } catch (KeyStoreException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("No se ha podido guardar el certificado y la clave privada en el KeyStore");
        }

        // Se guarda el KeyStore en un fichero
        Path keystorePath = Paths.get(user.getUsername() + "KeyStore.pfx");
        try (OutputStream fos = Files.newOutputStream(keystorePath)) {
            //Se guarda el KeyStore en el fichero
            ks.store(fos, secretKey);
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException("No se ha podido guardar el KeyStore en el fichero");
        }
    }

    @Override
    public Single<Either<String, Boolean>> delete(String username) {
        username = Base64.getUrlEncoder().encodeToString(username.getBytes());
        return usersDAO.delete(username);
    }
}
