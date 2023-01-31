package org.jorgetargz.server.jakarta.security;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.security.enterprise.credential.BasicAuthenticationCredential;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.server.dao.excepciones.DatabaseException;
import org.jorgetargz.server.dao.excepciones.NotFoundException;
import org.jorgetargz.server.dao.excepciones.UnauthorizedException;
import org.jorgetargz.server.domain.services.ServicesUsers;
import org.jorgetargz.server.domain.services.excepciones.ValidationException;
import org.jorgetargz.server.jakarta.common.Constantes;
import org.jorgetargz.utils.modelo.User;

import java.util.Set;

import static jakarta.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

@Log4j2
@Named(Constantes.IDENTITY_STORE)
public class IdentityStoreImpl implements IdentityStore {

    private final ServicesUsers serviciosLogin;

    @Override
    public int priority() {
        return 10;
    }

    @Inject
    public IdentityStoreImpl(ServicesUsers serviciosLogin) {
        this.serviciosLogin = serviciosLogin;
    }

    @Override
    public CredentialValidationResult validate(Credential credential) {

        if (credential instanceof BasicAuthenticationCredential basicAuthenticationCredential) {
            User loggedUser;
            try {
                loggedUser = serviciosLogin.scCheckCredentials(basicAuthenticationCredential.getCaller(), basicAuthenticationCredential.getPassword().getValue());
                return new CredentialValidationResult(loggedUser.getUsername(), Set.of(loggedUser.getRole()));
            } catch (DatabaseException | NotFoundException e) {
                return NOT_VALIDATED_RESULT;
            } catch (UnauthorizedException | ValidationException e) {
                return INVALID_RESULT;
            }
        } else {
            return null;
        }
    }
}
