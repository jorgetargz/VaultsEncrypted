package org.jorgetargz.client.gui.screens.vault;

import io.reactivex.rxjava3.schedulers.Schedulers;
import jakarta.inject.Inject;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.ReadOnlyObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import org.jorgetargz.client.domain.services.MessagesServices;
import org.jorgetargz.client.gui.screens.common.ScreenConstants;
import org.jorgetargz.utils.modelo.Message;
import org.jorgetargz.utils.modelo.Vault;

public class VaultsViewModel {

    private final MessagesServices messageServices;
    private final ObjectProperty<VaultState> state;

    @Inject
    public VaultsViewModel(MessagesServices messageServices) {
        this.messageServices = messageServices;
        state = new SimpleObjectProperty<>(new VaultState(null, null,  false, false, false));
    }

    public ReadOnlyObjectProperty<VaultState> getState() {
        return state;
    }

    public void loadMessages(Vault credentials) {
        state.set(new VaultState(null, null, false, true, false));
        messageServices.getAll(credentials.getName(), credentials.getUsernameOwner(), credentials.getPassword())
                .subscribeOn(Schedulers.single())
                .subscribe(either -> {
                    if (either.isLeft())
                        state.set(new VaultState(either.getLeft(), null, false, false, true));
                    else
                        state.set(new VaultState(null, either.get(), false, false, true));
                });
    }

    public void saveMessage(Vault vault, String content) {
        if (vault != null && content != null && !content.isEmpty()) {
            Message message = Message.builder()
                    .idVault(vault.getId())
                    .contentUnsecured(content)
                    .build();
            state.set(new VaultState(null, null, false, true, false));
            messageServices.save(message, vault.getPassword())
                    .subscribeOn(Schedulers.single())
                    .subscribe(either -> {
                        if (either.isLeft())
                            state.set(new VaultState(either.getLeft(), null, false, false, true));
                        else {
                            state.set(new VaultState(null, null, true, false, true));
                            loadMessages(vault);
                        }
                    });
        } else {
            state.set(new VaultState(ScreenConstants.FILL_ALL_THE_INPUTS, null, false, false, true));
        }
    }

    public void updateMessage(Vault vault, Message message, String newContent) {
        if (vault != null && message != null && newContent != null && !newContent.isEmpty()) {
            message.setContentUnsecured(newContent);
            state.set(new VaultState(null, null, false, true, false));
            messageServices.update(message, vault.getPassword())
                    .subscribeOn(Schedulers.single())
                    .subscribe(either -> {
                        if (either.isLeft())
                            state.set(new VaultState(either.getLeft(), null, false, false, true));
                        else {
                            state.set(new VaultState(null, null, true, false, true));
                            loadMessages(vault);
                        }
                    });
        } else {
            state.set(new VaultState(ScreenConstants.FILL_ALL_THE_INPUTS, null, false, false, true));
        }
    }

    public void deleteMessage(Vault vault, Message message) {
        if (vault != null && message != null) {
            state.set(new VaultState(null, null, false, true, false));
            messageServices.delete(message.getId())
                    .subscribeOn(Schedulers.single())
                    .subscribe(either -> {
                        if (either.isLeft())
                            state.set(new VaultState(either.getLeft(), null, false, false, true));
                        else {
                            state.set(new VaultState(null, null, true, false, true));
                            loadMessages(vault);
                        }
                    });
        } else {
            state.set(new VaultState(ScreenConstants.FILL_ALL_THE_INPUTS, null, false, false, true));
        }
    }

    public void clenState() {
        state.setValue(new VaultState(null, null, false, false, false));
    }
}