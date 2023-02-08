package org.jorgetargz.server.domain.services.impl;


import jakarta.inject.Inject;
import lombok.extern.log4j.Log4j2;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jorgetargz.security.EncriptacionAES;
import org.jorgetargz.security.EncriptacionRSA;
import org.jorgetargz.server.dao.UsersDao;
import org.jorgetargz.server.domain.common.Constantes;
import org.jorgetargz.server.domain.services.ServicesUsers;
import org.jorgetargz.server.domain.services.excepciones.ValidationException;
import org.jorgetargz.server.jakarta.security.JWTBlackList;
import org.jorgetargz.utils.modelo.ContentCiphedAES;
import org.jorgetargz.utils.modelo.User;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

@Log4j2
public class ServicesUsersImpl implements ServicesUsers, Serializable {

    private final UsersDao daoLogin;
    private final JWTBlackList jwtBlackList;
    private final EncriptacionAES encriptacionAES;
    private final EncriptacionRSA encriptacionRSA;
    private final KeyPair keyPair;

    @Inject
    public ServicesUsersImpl(UsersDao daoLogin, JWTBlackList jwtBlackList,
                             EncriptacionAES encriptacionAES, EncriptacionRSA encriptacionRSA, KeyPair keyPair
    ) {
        this.daoLogin = daoLogin;
        this.jwtBlackList = jwtBlackList;
        this.encriptacionAES = encriptacionAES;
        this.encriptacionRSA = encriptacionRSA;
        this.keyPair = keyPair;
    }

    @Override
    public User scGet(String username) {
        if (username == null) {
            log.warn(Constantes.USERNAME_EMPTY);
            throw new ValidationException(Constantes.USERNAME_EMPTY);
        }
        return daoLogin.get(username);
    }

    @Override
    public User scGetBase64(String username) {
        if (username == null) {
            log.warn(Constantes.USERNAME_EMPTY);
            throw new ValidationException(Constantes.USERNAME_EMPTY);
        }
        username = new String(Base64.getUrlDecoder().decode(username));
        return daoLogin.get(username);
    }

    @Override
    public User scSave(User user) {
        ContentCiphedAES publicKeyEncrypted = user.getPublicKeyEncrypted();
        String passwordEncryptedBase64 = user.getEncryptedPasswordOfPublicKeyEncrypted();

        //Se decodifica de Base64 la clave pública encriptada
        byte[] passwordEncrypted = Base64.getUrlDecoder().decode(passwordEncryptedBase64);

        //Se desencripta la contraseña con la clave privada del servidor
        byte[] passwordDecrypted;
        try {
            passwordDecrypted = encriptacionRSA.desencriptar(passwordEncrypted, keyPair.getPrivate());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            log.error(e.getMessage(), e);
            throw new ValidationException(Constantes.ERROR_AL_DESENCRIPTAR_LA_CLAVE_CON_LA_CLAVE_PRIVADA_DEL_SERVIDOR);
        }

        //Se desencripta la clave pública con la contraseña
        String publicKeyBase64 = encriptacionAES.desencriptar(publicKeyEncrypted, new String(passwordDecrypted));

        //Se decodifica la clave pública de Base64
        byte[] publicKeyBytes = Base64.getUrlDecoder().decode(publicKeyBase64);

        //Se crea un objeto PublicKey a partir del keySpec
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey;
        try {
            publicKey = KeyFactory.getInstance(Constantes.RSA).generatePublic(x509Spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
            throw new ValidationException(Constantes.ERROR_AL_CREAR_LA_CLAVE_PUB);
        }

        //Se crea un certificado con la clave pública del usuario firmado con la clave privada del servidor
        //Se crea un certificado firmado con la clave pública
        X500Name nombre = new X500Name(Constantes.CN + user.getUsername());
        X500Name issuer = new X500Name(Constantes.CN_SERVER);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, //issuer
                BigInteger.valueOf(1), //serial number
                Date.from(LocalDate.now().atStartOfDay().toInstant(ZoneOffset.UTC)), //not valid before
                Date.from(LocalDate.now().plus(1, ChronoUnit.YEARS).atStartOfDay().toInstant(ZoneOffset.UTC)), //not valid after
                nombre, //subject
                publicKey //public key
        );

        //Se firma el certificado con la clave privada
        ContentSigner signer;
        try {
            signer = new JcaContentSignerBuilder(Constantes.SHA_1_WITH_RSA_ENCRYPTION).build(keyPair.getPrivate());
        } catch (OperatorCreationException e) {
            log.error(e.getMessage(), e);
            throw new ValidationException(Constantes.ERROR_AL_FIRMAR_EL_CERTIFICADO);
        }

        //Se obtiene el certificado
        X509Certificate certificate;
        try {
            certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        } catch (CertificateException e) {
            log.error(e.getMessage(), e);
            throw new ValidationException(Constantes.ERROR_AL_OBTENER_EL_CERTIFICADO);
        }

        //Pasar el certificado a base64
        String certificadoBase64;
        try {
            certificadoBase64 = Base64.getUrlEncoder().encodeToString(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new ValidationException(Constantes.ERROR_AL_CODIFICAR_EL_CERTIFICADO_A_BASE_64);
        }

        //Se guarda el certificado en base64 en el usuario para que se guarde en la base de datos
        user.setCertificate(certificadoBase64);

        return daoLogin.save(user);
    }

    @Override
    public void scLogout(String authorization) {
        String[] headerFields = authorization.split(Constantes.WHITE_SPACE);
        if (headerFields.length == 2) {
            String token = headerFields[1];
            jwtBlackList.getJWTBlackList().add(token);
        }
    }

    @Override
    public void scDelete(String username) {
        username = new String(Base64.getUrlDecoder().decode(username));
        daoLogin.delete(username);
    }

}