package org.jorgetargz.client.dao.vault_api.utils;

import jakarta.inject.Inject;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;
import org.jorgetargz.client.dao.common.Constantes;

import java.io.IOException;

public class AuthorizationInterceptor implements Interceptor {


    private final CacheAuthorization ca;

    @Inject
    public AuthorizationInterceptor(CacheAuthorization ca) {
        this.ca = ca;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request original = chain.request().newBuilder()
                .addHeader(Constantes.PROTOCOL_REQUEST, Constantes.HTTP_2_0)
                .addHeader(Constantes.ACCEPT, Constantes.APPLICATION_JSON)
                .method(chain.request().method(), chain.request().body())
                .build();
        Request request;

        // Send request with the cached JWT if present
        if (ca.getJwtAuth() != null) {
            request = original.newBuilder()
                    .header(Constantes.AUTHORIZATION, ca.getJwtAuth())
                    .build();
        } else {
            request = original;
        }

        // Save the JWT in the cache
        Response response = chain.proceed(request);
        if (response.header(Constantes.AUTHORIZATION) != null)
            ca.setJwtAuth(response.header(Constantes.AUTHORIZATION));

        // Re-authenticate if the token is expired
        String tokenExpiredHeader = response.header(Constantes.TOKEN_EXPIRED);
        if (tokenExpiredHeader != null && tokenExpiredHeader.equals(Constantes.TRUE)) {
            response.close();
            request = original.newBuilder()
                    .header(Constantes.AUTHORIZATION, ca.getCertificateAuth()).build();
            response = chain.proceed(request);
            if (response.header(Constantes.AUTHORIZATION) != null)
                ca.setJwtAuth(response.header(Constantes.AUTHORIZATION));
            return response;
        }

        return response;
    }
}
