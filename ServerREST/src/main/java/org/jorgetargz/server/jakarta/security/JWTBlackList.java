package org.jorgetargz.server.jakarta.security;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

import java.util.ArrayList;
import java.util.List;

public class JWTBlackList {

    @Produces
    @Singleton
    public List<String> getJWTBlackList() {
        return new ArrayList<>();
    }
}
