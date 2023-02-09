package org.jorgetargz.security;

import java.security.*;

public interface SignUtils {

    byte[] sign(PrivateKey privateKey, byte[] data) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException;

    boolean verifySign(PublicKey publicKey, byte[] signature, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;
}
