package org.jorgetargz.client.dao.impl;

import com.google.gson.Gson;
import io.reactivex.rxjava3.core.Single;
import io.vavr.control.Either;
import jakarta.inject.Inject;
import org.jorgetargz.client.dao.UsersDAO;
import org.jorgetargz.client.dao.vault_api.UsersAPI;
import org.jorgetargz.utils.modelo.User;

public class UsersDAOImpl extends GenericDAO implements UsersDAO {

    private final UsersAPI usersAPI;

    @Inject
    public UsersDAOImpl(Gson gson, UsersAPI usersAPI) {
        super(gson);
        this.usersAPI = usersAPI;
    }

    @Override
    public Single<Either<String, User>> save(User user) {
        return safeAPICall(usersAPI.create(user));
    }

    @Override
    public Single<Either<String, Boolean>> delete(String username) {
        return safeAPICallResponseVoid(usersAPI.delete(username));
    }

}
