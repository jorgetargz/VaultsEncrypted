package org.jorgetargz.client.domain.services;

import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import org.jorgetargz.utils.modelo.Vault;

import java.util.List;

public interface VaultServices {

    Single<Either<String, List<Vault>>> getAll();

    Vault get(String vaultName, String username, String password);

    Single<Either<String, Vault>> save(Vault vault);

    Single<Either<String, Vault>> share(Vault vault, String username);

    Single<Either<String, Boolean>> delete(int vaultId);
}
