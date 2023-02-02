package org.jorgetargz.client.dao.impl;

import com.google.gson.Gson;
import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import jakarta.inject.Inject;
import org.jorgetargz.client.dao.SecurityDAO;
import org.jorgetargz.client.dao.vault_api.SecurityAPI;

public class SecurityDAOImpl extends GenericDAO implements SecurityDAO {

    private final SecurityAPI securityAPI;

    @Inject
    public SecurityDAOImpl(Gson gson, SecurityAPI securityAPI) {
        super(gson);
        this.securityAPI = securityAPI;
    }

    @Override
    public Single<Either<String, String>> getPublicKey() {
        return safeAPICall(securityAPI.getPublicKey());
    }
}
