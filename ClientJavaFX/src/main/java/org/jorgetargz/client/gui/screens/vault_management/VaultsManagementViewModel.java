package org.jorgetargz.client.gui.screens.vault_management;

import io.reactivex.rxjava3.schedulers.Schedulers;
import jakarta.inject.Inject;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.ReadOnlyObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import org.jorgetargz.client.dao.vault_api.utils.CacheAuthorization;
import org.jorgetargz.client.domain.services.VaultServices;
import org.jorgetargz.client.gui.screens.common.ScreenConstants;
import org.jorgetargz.utils.modelo.Vault;

public class VaultsManagementViewModel {

    private final VaultServices vaultServices;
    private final CacheAuthorization cacheAuthorization;
    private final ObjectProperty<VaultsManagementState> state;

    @Inject
    public VaultsManagementViewModel(VaultServices vaultServices, CacheAuthorization cacheAuthorization) {
        this.vaultServices = vaultServices;
        this.cacheAuthorization = cacheAuthorization;
        state = new SimpleObjectProperty<>(new VaultsManagementState(null, null, null, false, false, false));
    }

    public ReadOnlyObjectProperty<VaultsManagementState> getState() {
        return state;
    }

    public void doDelete(Vault vault) {
        if (vault != null) {
            state.set(new VaultsManagementState(null, null, null, false, true, false));
            vaultServices.delete(vault.getId())
                    .subscribeOn(Schedulers.single())
                    .subscribe(either -> {
                        if (either.isLeft())
                            state.set(new VaultsManagementState(either.getLeft(), null, null, false, false, true));
                        else {
                            state.set(new VaultsManagementState(null, null, null, true, false, true));
                            loadVaults();
                        }
                    });
        } else {
            state.set(new VaultsManagementState(ScreenConstants.FILL_ALL_THE_INPUTS, null, null, false, false, true));
        }
    }

    public void changePassword(Vault vault, String oldPassword, String newPassword) {
        if (vault != null && oldPassword != null && !oldPassword.isEmpty() && newPassword != null && !newPassword.isEmpty()) {
            state.set(new VaultsManagementState(null, null, null, false, true, false));
            vault.setKey(oldPassword);
            vaultServices.changePassword(vault, newPassword)
                    .subscribeOn(Schedulers.single())
                    .subscribe(either -> {
                        if (either.isLeft())
                            state.set(new VaultsManagementState(either.getLeft(), null, null, false, false, true));
                        else {
                            state.set(new VaultsManagementState(null, null, null, true, false, true));
                        }
                    });
        } else {
            state.set(new VaultsManagementState(ScreenConstants.FILL_ALL_THE_INPUTS, null, null, false, false, true));
        }
    }

    public void loadVaults() {
        state.set(new VaultsManagementState(null, null, null, false, true, false));
        vaultServices.getAll()
                .subscribeOn(Schedulers.single())
                .subscribe(either -> {
                    if (either.isLeft())
                        state.set(new VaultsManagementState(either.getLeft(), null, null, false, false, true));
                    else {
                        state.set(new VaultsManagementState(null, either.get(), null, false, false, true));
                    }
                });
    }

    public void openMyVault(Vault vault, String passwordText) {
        if (vault != null && passwordText != null && !passwordText.isEmpty()) {
            state.set(new VaultsManagementState(null, null, null, false, true, false));
            vaultServices.get(vault.getName(), vault.getUsernameOwner(), passwordText)
                    .subscribeOn(Schedulers.single())
                    .subscribe(either -> {
                        if (either.isLeft())
                            state.set(new VaultsManagementState(either.getLeft(), null, null, false, false, true));
                        else {
                            Vault credential = Vault.builder()
                                    .id(either.get().getId())
                                    .name(vault.getName())
                                    .usernameOwner(vault.getUsernameOwner())
                                    .key(passwordText)
                                    .build();
                            state.set(new VaultsManagementState(null, null, credential, false, false, true));
                        }
                    });
        } else {
            state.set(new VaultsManagementState(ScreenConstants.FILL_ALL_THE_INPUTS, null, null, false, false, true));
        }
    }

    public void openOtherUserVault(String usernameOwnerText, String nameVaultText, String passwordText) {
        if (usernameOwnerText != null && !usernameOwnerText.isEmpty() && nameVaultText != null && !nameVaultText.isEmpty() && passwordText != null && !passwordText.isEmpty()) {
            state.set(new VaultsManagementState(null, null, null, false, true, false));
            vaultServices.get(nameVaultText, usernameOwnerText, passwordText)
                    .subscribeOn(Schedulers.single())
                    .subscribe(either -> {
                        if (either.isLeft())
                            state.set(new VaultsManagementState(either.getLeft(), null, null, false, false, true));
                        else {
                            Vault credential = Vault.builder()
                                    .id(either.get().getId())
                                    .name(nameVaultText)
                                    .usernameOwner(usernameOwnerText)
                                    .key(passwordText)
                                    .build();
                            state.set(new VaultsManagementState(null, null, credential, false, false, true));
                        }
                    });
        } else {
            state.set(new VaultsManagementState(ScreenConstants.FILL_ALL_THE_INPUTS, null, null, false, false, true));
        }
    }

    public void createVault(String username, String name, String password, boolean readByAll, boolean writeByAll) {
        if (username != null && !username.isEmpty()
                && name != null && !name.isEmpty()
                && password != null && !password.isEmpty()) {
            state.set(new VaultsManagementState(null, null, null, false, true, false));
            Vault vault = Vault.builder()
                    .name(name)
                    .usernameOwner(username)
                    .key(password)
                    .readByAll(readByAll)
                    .writeByAll(writeByAll)
                    .build();
            vaultServices.save(vault, cacheAuthorization.getPassword())
                    .subscribeOn(Schedulers.single())
                    .subscribe(either -> {
                        if (either.isLeft())
                            state.set(new VaultsManagementState(either.getLeft(), null, null, false, false, true));
                        else {
                            state.set(new VaultsManagementState(null, null, null, true, false, true));
                            loadVaults();
                        }
                    });
        } else {
            state.set(new VaultsManagementState(ScreenConstants.FILL_ALL_THE_INPUTS, null, null, false, false, true));
        }
    }

    public void clenState() {
        state.setValue(new VaultsManagementState(null, null, null, false, false, false));
    }
}