package org.jorgetargz.client.dao;

import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import org.jorgetargz.utils.modelo.Vault;

import java.util.List;

public interface VaultDAO {

    Single<Either<String, List<Vault>>> getAll();

    Single<Either<String, Vault>> get(String vaultName, String username, String password);

    Single<Either<String, Vault>> save(Vault vault);

    Single<Either<String, Boolean>> changePassword(Vault credentials, String password);

    Single<Either<String, Boolean>> delete(int vaultId);
}
