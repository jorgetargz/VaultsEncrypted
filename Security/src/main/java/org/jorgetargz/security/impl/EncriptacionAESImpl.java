package org.jorgetargz.security.impl;

import lombok.extern.log4j.Log4j2;
import org.jorgetargz.utils.modelo.ContentCiphedAES;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

@Log4j2
public class EncriptacionAESImpl implements org.jorgetargz.security.EncriptacionAES {

    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
    private static final String AES = "AES";
    private static final String PBKDF_2_WITH_HMAC_SHA_256 = "PBKDF2WithHmacSHA256";
    private static final int ITERACIONES = 65536;
    private static final int KEY_LENGTH = 256;
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 128;

    @Override
    public ContentCiphedAES encriptar(String strToEncrypt, String secret) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            byte[] salt = new byte[SALT_LENGTH];
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(iv);
            sr.nextBytes(salt);

            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            SecretKeySpec secretKey = getSecretKeySpec(secret, salt);
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            byte[] cipherText = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8));

            ContentCiphedAES contentCiphedAES = new ContentCiphedAES();
            contentCiphedAES.setIv(Base64.getEncoder().encodeToString(iv));
            contentCiphedAES.setSalt(Base64.getEncoder().encodeToString(salt));
            contentCiphedAES.setCipherText(Base64.getEncoder().encodeToString(cipherText));

            return contentCiphedAES;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    @Override
    public String desencriptar(ContentCiphedAES contentCiphedAES, String secret) {
        try {
            byte[] iv = Base64.getDecoder().decode(contentCiphedAES.getIv());
            byte[] salt = Base64.getDecoder().decode(contentCiphedAES.getSalt());
            byte[] cipherText = Base64.getDecoder().decode(contentCiphedAES.getCipherText());

            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            SecretKeySpec secretKey = getSecretKeySpec(secret, salt);
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
            return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    private SecretKeySpec getSecretKeySpec(String secret, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF_2_WITH_HMAC_SHA_256);
        KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt, ITERACIONES, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), AES);
    }
}