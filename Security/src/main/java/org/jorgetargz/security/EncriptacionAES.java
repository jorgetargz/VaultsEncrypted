package org.jorgetargz.security;

import org.jorgetargz.utils.modelo.ContentCiphedAES;

public interface EncriptacionAES {

    ContentCiphedAES encriptar(String texto, String secret);

    String desencriptar(ContentCiphedAES contentCiphedAES, String secret);

}
