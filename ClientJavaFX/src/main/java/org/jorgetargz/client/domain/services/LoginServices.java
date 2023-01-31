package org.jorgetargz.client.domain.services;

import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import org.jorgetargz.utils.modelo.User;

public interface LoginServices {

    Single<Either<String, User>> scLogin(String username, String password);

    Single<Either<String, Boolean>> scLogout();

}
