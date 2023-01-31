package org.jorgetargz.server.dao;

import org.jorgetargz.utils.modelo.User;

public interface UsersDao {

    User get(String username);

    User save(User user);

    void delete(String username);
}
