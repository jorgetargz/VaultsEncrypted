package org.jorgetargz.security.impl;

import org.jorgetargz.security.SignUtils;

import java.security.*;

public class SignUtilsImpl implements SignUtils {

    public static final String SHA_256_WITH_RSA = "SHA256withRSA";

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] data) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        Signature sign = Signature.getInstance(SHA_256_WITH_RSA);
        sign.initSign(privateKey);
        sign.update(data);
        return sign.sign();
    }

    @Override
    public boolean verifySign(PublicKey publicKey, byte[] signature, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance(SHA_256_WITH_RSA);
        sign.initVerify(publicKey);
        sign.update(data);
        return sign.verify(signature);
    }
}