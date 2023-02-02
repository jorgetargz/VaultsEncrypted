package org.jorgetargz.server.jakarta.rest;


import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.jorgetargz.utils.common.ConstantesAPI;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Path(ConstantesAPI.PATH_SECURITY)
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class RESTSecurity {

    private final KeyPair rsaKeyPair;

    @Inject
    public RESTSecurity(KeyPair rsaKeyPair) {
        this.rsaKeyPair = rsaKeyPair;
    }

    @GET
    @Path(ConstantesAPI.PUBLIC_KEY_PATH)
    public String getPublicKey() {
        PublicKey clavePublica = rsaKeyPair.getPublic();
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(clavePublica.getEncoded());
        return Base64.getUrlEncoder().encodeToString(x509Spec.getEncoded());
    }

}