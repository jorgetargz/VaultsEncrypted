package org.jorgetargz.server.domain.services;


import org.jorgetargz.server.dao.excepciones.UnauthorizedException;
import org.jorgetargz.server.domain.services.excepciones.ValidationException;
import org.jorgetargz.utils.modelo.User;

public interface ServicesUsers {

    User scGet(String username);

    User scSave(User user);

    User scCheckCredentials(String username, char[] password) throws UnauthorizedException, ValidationException;

    void scLogout(String authorization);

    void scDelete(String username);
}
