package org.jorgetargz.client.dao;

import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import org.jorgetargz.utils.modelo.User;


public interface LoginDAO {

    Single<Either<String, User>> login(String authorization);

    Single<Either<String, Boolean>> logout(String authorization);
}
