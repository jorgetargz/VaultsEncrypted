package org.jorgetargz.client.gui.screens.login;

import org.jorgetargz.utils.modelo.User;

public record LoginState(
        User user,
        String error,
        boolean isLoading,
        boolean isLoaded
) {
}
