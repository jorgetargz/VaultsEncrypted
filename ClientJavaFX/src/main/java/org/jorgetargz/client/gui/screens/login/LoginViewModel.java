package org.jorgetargz.client.gui.screens.login;

import org.jorgetargz.client.dao.vault_api.utils.CacheAuthorization;
import org.jorgetargz.client.gui.screens.common.ScreenConstants;
import org.jorgetargz.client.domain.services.LoginServices;
import io.reactivex.rxjava3.schedulers.Schedulers;
import jakarta.inject.Inject;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.ReadOnlyObjectProperty;
import javafx.beans.property.SimpleObjectProperty;

public class LoginViewModel {

    private final LoginServices loginServices;
    private final CacheAuthorization cacheAuthorization;
    private final ObjectProperty<LoginState> state;

    @Inject
    public LoginViewModel(LoginServices loginServices, CacheAuthorization cacheAuthorization) {
        this.loginServices = loginServices;
        this.cacheAuthorization = cacheAuthorization;
        state = new SimpleObjectProperty<>(new LoginState(null, null, false, false));
    }

    public ReadOnlyObjectProperty<LoginState> getState() {
        return state;
    }

    public void doLogin(String username, String password) {
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            state.set(new LoginState(null, ScreenConstants.FILL_ALL_THE_INPUTS, false, true));
            return;
        }
        state.set(new LoginState(null, null, true, false));
        loginServices.scLogin(username, password)
                .observeOn(Schedulers.single())
                .subscribe(either -> {
                    if (either.isLeft())
                        state.set(new LoginState(null, either.getLeft(), false,true));
                    else {
                        cacheAuthorization.setPassword(password);
                        state.set(new LoginState(either.get(), null, false, true));
                    }
                });
    }

    public void clenState() {
        state.setValue(new LoginState(null, null, false, false));
    }
}
