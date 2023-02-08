package org.jorgetargz.client.dao.impl;

import com.google.gson.Gson;
import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import jakarta.inject.Inject;
import org.jorgetargz.client.dao.VaultDAO;
import org.jorgetargz.client.dao.vault_api.VaultAPI;
import org.jorgetargz.utils.modelo.Vault;

import java.util.List;

public class VaultsDAOImpl extends GenericDAO implements VaultDAO {

    private final VaultAPI vaultAPI;

    @Inject
    public VaultsDAOImpl(Gson gson, VaultAPI vaultAPI) {
        super(gson);
        this.vaultAPI = vaultAPI;
    }

    @Override
    public Single<Either<String, List<Vault>>> getAll() {
        return safeAPICall(vaultAPI.getVaults());
    }

    @Override
    public Single<Either<String, Vault>> get(String vaultName, String username) {
        return safeAPICall(vaultAPI.getVault(vaultName, username));
    }

    @Override
    public Single<Either<String, Vault>> save(Vault vault) {
        return safeAPICall(vaultAPI.createVault(vault));
    }

    @Override
    public Single<Either<String, Vault>> share(Vault vault, String username, String passwordEncWithUserPubKey) {
        return safeAPICall(vaultAPI.shareVault(vault, username, passwordEncWithUserPubKey));
    }

    @Override
    public Single<Either<String, Boolean>> delete(int vaultId) {
        return safeAPICallResponseVoid(vaultAPI.deleteVault(vaultId));
    }
}