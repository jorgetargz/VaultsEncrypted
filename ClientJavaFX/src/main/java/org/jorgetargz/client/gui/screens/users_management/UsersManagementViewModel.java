package org.jorgetargz.client.gui.screens.users_management;

import io.reactivex.rxjava3.schedulers.Schedulers;
import jakarta.inject.Inject;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.ReadOnlyObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import org.jorgetargz.client.domain.services.UsersServices;
import org.jorgetargz.client.gui.screens.common.ScreenConstants;
import org.jorgetargz.utils.modelo.User;

public class UsersManagementViewModel {

    private final UsersServices usersServices;
    private final ObjectProperty<UsersManagementState> state;

    @Inject
    public UsersManagementViewModel(UsersServices usersServices) {
        this.usersServices = usersServices;
        state = new SimpleObjectProperty<>(new UsersManagementState(null, false, false, false));
    }

    public ReadOnlyObjectProperty<UsersManagementState> getState() {
        return state;
    }

    public void doRegister(String inputUsername, String inputPassword) {
        if (inputUsername != null && !inputUsername.isEmpty()
                && inputPassword != null && !inputPassword.isEmpty()) {
            User user = User.builder()
                    .username(inputUsername)
                    .password(inputPassword)
                    .build();
            state.set(new UsersManagementState(null, false, true, false));
                usersServices.save(user)
                        .subscribeOn(Schedulers.single())
                        .subscribe(either -> {
                            if (either.isLeft())
                                state.set(new UsersManagementState(either.getLeft(), false, false, true));
                            else {
                                state.set(new UsersManagementState(null, true, false, true));
                            }
                        });
        } else {
            state.set(new UsersManagementState(ScreenConstants.FILL_ALL_THE_INPUTS, false, false, true));
        }
    }

    public void doDelete(String inputUsername) {
        if (inputUsername != null && !inputUsername.isEmpty()) {
            state.set(new UsersManagementState(null, false, true, false));
            usersServices.delete(inputUsername)
                    .subscribeOn(Schedulers.single())
                    .subscribe(either -> {
                        if (either.isLeft())
                            state.set(new UsersManagementState(either.getLeft(), false, false, true));
                        else {
                            state.set(new UsersManagementState(null, true, false, true));
                        }
                    });
        } else {
            state.set(new UsersManagementState(ScreenConstants.FILL_ALL_THE_INPUTS, false, false, true));
        }
    }

    public void clenState() {
        state.setValue(new UsersManagementState(null, false, false, false));
    }
}