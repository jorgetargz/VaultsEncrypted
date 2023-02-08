package org.jorgetargz.security;

import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public interface KeyStoreUtils {

    KeyStore createKeyStoreWithAutoSignedCert(String keystorePassword, String name, PublicKey publicKey, PrivateKey privateKey) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, OperatorCreationException;

    KeyStore createKeyStore(String keystorePassword, X509Certificate certificate, PrivateKey privateKey) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException;

    KeyStore getKeyStore(Path keystorePath, String keystorePassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException;

    PublicKey getPublicKey(KeyStore keyStore, String alias) throws KeyStoreException;

    PrivateKey getPrivateKey(KeyStore keyStore, String alias, String password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException;
}
