package org.jorgetargz.client.gui.screens.vault;

import org.jorgetargz.utils.modelo.Message;

import java.util.List;

public record VaultState(
        String error,
        List<Message> messages,
        boolean operationDone,
        boolean isLoading,
        boolean isLoaded
) {
}
