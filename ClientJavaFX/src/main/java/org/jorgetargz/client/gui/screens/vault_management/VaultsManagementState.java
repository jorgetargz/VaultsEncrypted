package org.jorgetargz.client.gui.screens.vault_management;

import org.jorgetargz.utils.modelo.Vault;

import java.util.List;

public record VaultsManagementState(
        String error,
        List<Vault> vaultsOwned,
        Vault vaultToOpen,
        boolean operationDone,
        boolean isLoading,
        boolean isLoaded
) {
}
