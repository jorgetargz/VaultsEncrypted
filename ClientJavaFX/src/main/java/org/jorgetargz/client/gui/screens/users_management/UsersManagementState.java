package org.jorgetargz.client.gui.screens.users_management;

public record UsersManagementState(
        String error,
        boolean operationDone,
        boolean isLoading,
        boolean isLoaded
) {
}
