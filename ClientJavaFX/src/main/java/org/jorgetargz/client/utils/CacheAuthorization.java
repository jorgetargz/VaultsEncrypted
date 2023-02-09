package org.jorgetargz.client.utils;

import jakarta.inject.Singleton;
import lombok.Data;

import java.security.PrivateKey;


@Data
@Singleton
public class CacheAuthorization {

    private String user;
    private String password;
    private String jwtAuth;
    private String certificateAuth;
    private PrivateKey privateKey;
}
