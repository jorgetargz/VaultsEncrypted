package org.jorgetargz.server.domain.services;


import org.jorgetargz.utils.modelo.User;

public interface ServicesUsers {

    User scGet(String username);

    User scSave(User user);

    void scLogout(String authorization);

    void scDelete(String username);
}
