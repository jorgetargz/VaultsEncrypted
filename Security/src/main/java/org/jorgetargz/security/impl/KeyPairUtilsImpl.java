package org.jorgetargz.security.impl;

import org.jorgetargz.security.KeyPairUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyPairUtilsImpl implements KeyPairUtils {

    @Override
    public KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator generadorRSA4096;
        generadorRSA4096 = KeyPairGenerator.getInstance("RSA");
        generadorRSA4096.initialize(keySize);
        return generadorRSA4096.generateKeyPair();
    }
}
