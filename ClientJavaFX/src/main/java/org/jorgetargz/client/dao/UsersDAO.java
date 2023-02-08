package org.jorgetargz.client.dao;

import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import org.jorgetargz.utils.modelo.User;

public interface UsersDAO {

    Single<Either<String, User>> get(String username);

    Single<Either<String, User>> save(User user);

    Single<Either<String, Boolean>> delete(String username);
}
