package org.jorgetargz.security.impl;

import lombok.extern.log4j.Log4j2;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jorgetargz.security.KeyStoreUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Log4j2
public class KeyStoreUtilsImpl implements KeyStoreUtils {

    private static final String PKCS_12 = "PKCS12";
    private static final String CN = "CN=";
    private static final String SHA_1_WITH_RSA_ENCRYPTION = "SHA1WithRSAEncryption";
    private static final String PRIVADA = "privada";
    private static final String PUBLICA = "publica";

    @Override
    public KeyStore createKeyStoreWithAutoSignedCert(String keystorePassword, String name, PublicKey publicKey, PrivateKey privateKey) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, OperatorCreationException {
        KeyStore ks;
        ks = KeyStore.getInstance(PKCS_12);
        ks.load(null, null);

        // Se convierte el password en un char[] para poder usarla en el KeyStore
        char[] secretKey = keystorePassword.toCharArray();

        X500Name subject = new X500Name(CN + name);
        X500Name issuer = new X500Name(CN + name);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, //issuer
                BigInteger.valueOf(1), //serial number
                Date.from(LocalDate.now().atStartOfDay().toInstant(ZoneOffset.UTC)), //not valid before
                Date.from(LocalDate.now().plus(1, ChronoUnit.YEARS).atStartOfDay().toInstant(ZoneOffset.UTC)), //not valid after
                subject, //subject
                publicKey //public key
        );

        //Se firma el certificado con la clave privada
        ContentSigner signer;
        signer = new JcaContentSignerBuilder(SHA_1_WITH_RSA_ENCRYPTION).build(privateKey);

        //Se obtiene el certificado
        X509Certificate certificate;
        certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        //Se añade la clave privada y el certificado al KeyStore
        ks.setKeyEntry(PRIVADA, privateKey, secretKey, new Certificate[]{certificate});
        ks.setCertificateEntry(PUBLICA, certificate);

        return ks;
    }

    @Override
    public KeyStore createKeyStore(String keystorePassword, X509Certificate certificate, PrivateKey privateKey) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore ks = KeyStore.getInstance(PKCS_12);
        ks.load(null, null);

        // Se convierte el password en un char[] para poder usarla en el KeyStore
        char[] secretKey = keystorePassword.toCharArray();

        //Se guarda el certificado en el KeyStore
        ks.setCertificateEntry(PUBLICA, certificate);
        //Se guarda la clave privada en el KeyStore con la misma secretKey que el KeyStore
        ks.setKeyEntry(PRIVADA, privateKey, secretKey, new Certificate[]{certificate});

        return ks;
    }

    @Override
    public KeyStore getKeyStore(Path keystorePath, String keystorePassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        char[] secretKey = keystorePassword.toCharArray();
        KeyStore keyStore = KeyStore.getInstance(PKCS_12); //KeySoreException
        keyStore.load(Files.newInputStream(keystorePath), secretKey); //IOException, NoSuchAlgorithmException, CertificateException
        return keyStore;
    }

    @Override
    public PublicKey getPublicKey(KeyStore keyStore, String alias) throws KeyStoreException {
        return keyStore.getCertificate(alias).getPublicKey();
    }

    @Override
    public PrivateKey getPrivateKey(KeyStore keyStore, String alias, String password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        char[] secretKey = password.toCharArray();
        return (PrivateKey) keyStore.getKey(alias, secretKey);
    }
}