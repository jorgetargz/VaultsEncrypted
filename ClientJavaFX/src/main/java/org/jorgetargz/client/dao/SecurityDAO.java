package org.jorgetargz.client.dao;

import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;

public interface SecurityDAO {

    Single<Either<String, String>> getPublicKey();
}
