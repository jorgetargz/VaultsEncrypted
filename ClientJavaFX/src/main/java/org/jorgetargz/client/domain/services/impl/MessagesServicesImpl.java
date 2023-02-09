package org.jorgetargz.client.domain.services.impl;

import com.nimbusds.jose.util.X509CertUtils;
import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import jakarta.inject.Inject;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.client.dao.MessagesDAO;
import org.jorgetargz.client.dao.UsersDAO;
import org.jorgetargz.client.domain.common.Constantes;
import org.jorgetargz.client.domain.services.MessagesServices;
import org.jorgetargz.client.utils.CacheAuthorization;
import org.jorgetargz.security.EncriptacionAES;
import org.jorgetargz.security.SignUtils;
import org.jorgetargz.utils.modelo.ContentCiphedAES;
import org.jorgetargz.utils.modelo.Message;
import org.jorgetargz.utils.modelo.User;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@Log4j2
public class MessagesServicesImpl implements MessagesServices {

    private final MessagesDAO messagesDAO;
    private final UsersDAO usersDAO;
    private final EncriptacionAES encriptacionAES;
    private final CacheAuthorization cacheAuthorization;
    private final SignUtils signUtils;

    @Inject
    public MessagesServicesImpl(MessagesDAO messagesDAO, UsersDAO usersDAO, EncriptacionAES encriptacionAES, CacheAuthorization cacheAuthorization, SignUtils signUtils) {
        this.messagesDAO = messagesDAO;
        this.usersDAO = usersDAO;
        this.encriptacionAES = encriptacionAES;
        this.cacheAuthorization = cacheAuthorization;
        this.signUtils = signUtils;
    }

    @Override
    public Single<Either<String, List<Message>>> getAll(String vaultName, String username, String password) {
        vaultName = Base64.getUrlEncoder().encodeToString(vaultName.getBytes());
        username = Base64.getUrlEncoder().encodeToString(username.getBytes());
        return messagesDAO.getAll(vaultName, username).map(either -> either.map(messages -> {
            messages.forEach(message -> {
                message.setContentUnsecured(encriptacionAES.desencriptar(message.getContentCiphedAES(), password));
                verifySignature(message);
            });
            return messages;
        }));
    }

    @Override
    public Single<Either<String, Message>> save(Message message, String password) {
        ContentCiphedAES contentCiphedAES = encriptacionAES.encriptar(message.getContentUnsecured(), password);
        String signatureBase64 = getSignatureBase64(contentCiphedAES);
        Message messageSigned = Message.builder()
                .idVault(message.getIdVault())
                .contentCiphedAES(contentCiphedAES)
                .signedBy(cacheAuthorization.getUser())
                .signature(signatureBase64)
                .build();
        return messagesDAO.save(messageSigned);
    }

    @Override
    public Single<Either<String, Message>> update(Message message, String password) {
        ContentCiphedAES contentCiphedAES = encriptacionAES.encriptar(message.getContentUnsecured(), password);
        String signatureBase64 = getSignatureBase64(contentCiphedAES);
        Message messageSigned = Message.builder()
                .id(message.getId())
                .idVault(message.getIdVault())
                .contentCiphedAES(contentCiphedAES)
                .signedBy(cacheAuthorization.getUser())
                .signature(signatureBase64)
                .build();
        return messagesDAO.update(messageSigned);
    }

    @Override
    public Single<Either<String, Boolean>> delete(int messageId) {
        return messagesDAO.delete(messageId);
    }

    private String getSignatureBase64(ContentCiphedAES contentCiphedAES) {
        String signatureBase64;
        try {
            byte[] signature = signUtils.sign(cacheAuthorization.getPrivateKey(), contentCiphedAES.getCipherText().getBytes());
            signatureBase64 = Base64.getUrlEncoder().encodeToString(signature);
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return signatureBase64;
    }

    private void verifySignature(Message message) {
        String usernameBase64 = Base64.getUrlEncoder().encodeToString(message.getSignedBy().getBytes());
        CompletableFuture<User> userCompletableFuture = new CompletableFuture<>();
        User user = null;
        try {
            usersDAO.get(usernameBase64)
                    .subscribe(eitherUser -> {
                        if (eitherUser.isLeft()) {
                            userCompletableFuture.completeExceptionally(
                                    new RuntimeException(eitherUser.getLeft())
                            );
                            log.error(eitherUser.getLeft());
                        } else {
                            userCompletableFuture.complete(eitherUser.get());
                        }
                    });
            user = userCompletableFuture.join();
        } catch (RuntimeException e) {
            log.error(e.getMessage(), e);
        }
        if (user == null) return;

        String certificateBase64 = user.getCertificate();
        X509Certificate certificate = X509CertUtils.parse(Base64.getUrlDecoder().decode(certificateBase64));

        //Se obtiene la clave pública del certificado
        PublicKey publicKey = certificate.getPublicKey();

        //Se verifica la firma del mensaje
        byte[] signature = Base64.getUrlDecoder().decode(message.getSignature().getBytes());
        try {
            signUtils.verifySign(publicKey, signature, message.getContentCiphedAES().getCipherText().getBytes());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(Constantes.COULDN_T_VERIFY_SIGNATURE);
        }
    }
}
