package org.jorgetargz.security;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public interface KeyPairUtils {

    KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException;
}
