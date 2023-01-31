package org.jorgetargz.client.gui.screens.main;

import org.jorgetargz.client.domain.services.LoginServices;
import jakarta.inject.Inject;
import javafx.application.Platform;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.ReadOnlyObjectProperty;
import javafx.beans.property.SimpleObjectProperty;

public class MainViewModel {

    private final LoginServices loginServices;
    private final ObjectProperty<MainState> state;

    @Inject
    public MainViewModel(LoginServices loginServices) {
        this.loginServices = loginServices;
        state = new SimpleObjectProperty<>(new MainState(null, false));
    }

    public ReadOnlyObjectProperty<MainState> getState() {
        return state;
    }

    public void doLogout() {
        loginServices.scLogout().subscribe(either -> {
            if (either.isLeft()) {
                state.set(new MainState(either.getLeft(), false));
            } else {
                state.set(new MainState(null, true));
            }
        });
    }

    public void doExit() {
        Platform.exit();
    }

    public void clearState() {
        state.set(new MainState(null, false));
    }

}
