package org.jorgetargz.client.dao.vault_api.di;

import com.google.gson.Gson;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import okhttp3.ConnectionPool;
import okhttp3.OkHttpClient;
import org.jorgetargz.client.dao.vault_api.*;
import org.jorgetargz.client.dao.vault_api.config.ConfigVaultAPI;
import org.jorgetargz.client.dao.vault_api.utils.AuthorizationInterceptor;
import retrofit2.Retrofit;
import retrofit2.adapter.rxjava3.RxJava3CallAdapterFactory;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.converter.scalars.ScalarsConverterFactory;

import java.util.concurrent.TimeUnit;


public class ProducerVaultAPI {

    @Produces
    @Singleton
    public Retrofit getRetrofit(ConfigVaultAPI configVaultAPI, AuthorizationInterceptor authorizationInterceptor, Gson gson) {

        OkHttpClient clientOK = new OkHttpClient.Builder()
                .connectionPool(new ConnectionPool(1, 1, TimeUnit.SECONDS))
                .addInterceptor(authorizationInterceptor)
                .build();

        return new Retrofit.Builder()
                .baseUrl(configVaultAPI.getBaseUrl())
                .addConverterFactory(GsonConverterFactory.create(gson))
                .addConverterFactory(ScalarsConverterFactory.create())
                .addCallAdapterFactory(RxJava3CallAdapterFactory.create())
                .client(clientOK)
                .build();

    }

    @Produces
    @Singleton
    public LoginAPI getLoginAPI(Retrofit retrofit) {
        return retrofit.create(LoginAPI.class);
    }

    @Produces
    @Singleton
    public UsersAPI getUsersAPI(Retrofit retrofit) {
        return retrofit.create(UsersAPI.class);
    }

    @Produces
    @Singleton
    public VaultAPI getVaultAPI(Retrofit retrofit) {
        return retrofit.create(VaultAPI.class);
    }

    @Produces
    @Singleton
    public MessagesAPI getMessagesAPI(Retrofit retrofit) {
        return retrofit.create(MessagesAPI.class);
    }

    @Produces
    @Singleton
    public SecurityAPI getSecurityAPI(Retrofit retrofit) {
        return retrofit.create(SecurityAPI.class);
    }

}
