package org.jorgetargz.client.dao;

import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;

import java.util.List;

public interface SecurityDAO {

    Single<Either<String, List<String>>> getPublicKey();
}
