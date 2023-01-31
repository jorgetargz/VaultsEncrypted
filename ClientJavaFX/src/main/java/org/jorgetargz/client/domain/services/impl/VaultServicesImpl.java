package org.jorgetargz.client.domain.services.impl;

import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import jakarta.inject.Inject;
import org.jorgetargz.client.dao.VaultDAO;
import org.jorgetargz.client.domain.services.VaultServices;
import org.jorgetargz.utils.modelo.Vault;

import java.util.Base64;
import java.util.List;

public class VaultServicesImpl implements VaultServices {

    private final VaultDAO vaultDAO;

    @Inject
    public VaultServicesImpl(VaultDAO vaultDAO) {
        this.vaultDAO = vaultDAO;
    }

    @Override
    public Single<Either<String, List<Vault>>> getAll() {
        return vaultDAO.getAll();
    }

    @Override
    public Single<Either<String, Vault>> get(String vaultName, String username, String password) {
        vaultName = Base64.getEncoder().encodeToString(vaultName.getBytes());
        username = Base64.getEncoder().encodeToString(username.getBytes());
        password = Base64.getEncoder().encodeToString(password.getBytes());
        return vaultDAO.get(vaultName, username, password);
    }

    @Override
    public Single<Either<String, Vault>> save(Vault vault) {
        return vaultDAO.save(vault);
    }

    @Override
    public Single<Either<String, Boolean>> changePassword(Vault credentials, String password) {
        password = Base64.getEncoder().encodeToString(password.getBytes());
        return vaultDAO.changePassword(credentials, password);
    }

    @Override
    public Single<Either<String, Boolean>> delete(int vaultId) {
        return vaultDAO.delete(vaultId);
    }
}
