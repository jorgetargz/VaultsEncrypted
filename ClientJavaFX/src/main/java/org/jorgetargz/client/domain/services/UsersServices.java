package org.jorgetargz.client.domain.services;

import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import org.jorgetargz.utils.modelo.User;

public interface UsersServices {

    Single<Either<String, User>> save(User user);

    Single<Either<String, Boolean>> delete(String username);
}
