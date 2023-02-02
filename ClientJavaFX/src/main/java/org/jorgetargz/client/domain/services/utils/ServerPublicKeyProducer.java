package org.jorgetargz.client.domain.services.utils;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.client.dao.SecurityDAO;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

@Log4j2
public class ServerPublicKeyProducer {

    @Produces
    @Singleton
    @Named("serverPublicKey")
    public PublicKey getServerPublicKey(SecurityDAO securityDAO) {
        CompletableFuture<PublicKey> publicKeyFuture = new CompletableFuture<>();
        securityDAO.getPublicKey()
                .subscribe(either -> {
                    if (either.isLeft())
                        throw new RuntimeException(either.getLeft());
                    else {
                        // Se decodifica la clave pública del servidor
                        byte[] clavePublicaServidorBytes =
                                Base64.getUrlDecoder().decode(either.get());

                        // Se obtiene la clave pública del servidor
                        X509EncodedKeySpec clavePublicaServidorSpec = new X509EncodedKeySpec(clavePublicaServidorBytes);
                        try {
                            publicKeyFuture.complete(KeyFactory.getInstance("RSA")
                                    .generatePublic(clavePublicaServidorSpec));
                        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                            log.error(e.getMessage(), e);
                            publicKeyFuture.completeExceptionally(e);
                            throw new RuntimeException("Error al obtener la clave pública del servidor");
                        }
                    }
                });
        return publicKeyFuture.join();
    }
}