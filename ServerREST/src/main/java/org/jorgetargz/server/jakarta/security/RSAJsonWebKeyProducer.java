package org.jorgetargz.server.jakarta.security;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import org.jorgetargz.server.dao.excepciones.UnauthorizedException;
import org.jorgetargz.server.jakarta.common.Constantes;
import lombok.extern.log4j.Log4j2;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.lang.JoseException;

@Log4j2
public class RSAJsonWebKeyProducer {

    @Produces
    @Singleton
    public RsaJsonWebKey getRsaJsonWebKey() {
        try {
            RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(Constantes.RSA_KEY_SIZE);
            rsaJsonWebKey.setKeyId(Constantes.KEY_ID);
            return rsaJsonWebKey;
        } catch (JoseException e) {
            log.error(e.getMessage(), e);
            throw new UnauthorizedException(e.getMessage());
        }

    }
}