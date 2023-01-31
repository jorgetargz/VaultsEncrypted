package org.jorgetargz.client.dao.vault_api.utils;

import jakarta.inject.Singleton;
import lombok.Data;


@Data
@Singleton
public class CacheAuthorization {

    private String user;
    private String password;
    private String jwtAuth;
    private String certificateAuth;
}
