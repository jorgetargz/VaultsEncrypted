package org.jorgetargz.client.gui.screens.vault_management;

import io.github.palexdev.materialfx.controls.MFXComboBox;
import io.github.palexdev.materialfx.controls.MFXPasswordField;
import io.github.palexdev.materialfx.controls.MFXTextField;
import io.github.palexdev.materialfx.controls.MFXToggleButton;
import jakarta.inject.Inject;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.Cursor;
import javafx.scene.control.Alert;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.client.gui.screens.common.BaseScreenController;
import org.jorgetargz.client.gui.screens.common.ScreenConstants;
import org.jorgetargz.utils.modelo.Vault;

@Log4j2
public class VaultsManagementController extends BaseScreenController {

    private final VaultsManagementViewModel vaultsManagementViewModel;

    @FXML
    private MFXToggleButton readByAll;
    @FXML
    private MFXToggleButton writeByAll;
    @FXML
    private MFXTextField txtNameVaultCreate;
    @FXML
    private MFXPasswordField txtPasswordCreate;
    @FXML
    private MFXTextField txtNameVaultOther;
    @FXML
    private MFXTextField txtUsernameOwner;
    @FXML
    private MFXPasswordField txtPasswordOther;
    @FXML
    private MFXComboBox<Vault> cmbOpenMyVaults;
    @FXML
    private MFXPasswordField txtPasswordMyVault;
    @FXML
    private MFXComboBox<Vault> cmbChangePassMyVaults;
    @FXML
    private MFXPasswordField txtVaultOldPassword;
    @FXML
    private MFXPasswordField txtVaultNewPassword;
    @FXML
    private MFXComboBox<Vault> cmbDeleteMyVaults;

    @Inject
    public VaultsManagementController(VaultsManagementViewModel vaultsManagementViewModel) {
        this.vaultsManagementViewModel = vaultsManagementViewModel;
    }

    public void initialize() {
        vaultsManagementViewModel.loadVaults();
        writeByAll.onActionProperty().set(event -> {
            if (writeByAll.isSelected()) {
                readByAll.setSelected(true);
            }
        });
        vaultsManagementViewModel.getState().addListener((observableValue, oldState, newState) -> {
            if (newState.error() != null) {
                Platform.runLater(() -> {
                    this.getPrincipalController().showAlert(Alert.AlertType.ERROR, ScreenConstants.ERROR, newState.error());
                    vaultsManagementViewModel.clenState();
                });
            }
            if (newState.vaultsOwned() != null) {
                Platform.runLater(() -> {
                    cmbDeleteMyVaults.getItems().setAll(newState.vaultsOwned());
                    cmbOpenMyVaults.getItems().setAll(newState.vaultsOwned());
                    cmbChangePassMyVaults.getItems().setAll(newState.vaultsOwned());
                });
            }
            if (newState.vaultToOpen() != null) {
                Platform.runLater(() -> this.getPrincipalController().onVaultOpened(newState.vaultToOpen()));
            }
            if (newState.operationDone()) {
                Platform.runLater(() -> {
                    this.getPrincipalController().showAlert(Alert.AlertType.INFORMATION, ScreenConstants.SUCCESS, ScreenConstants.OPERATION_DONE);
                    vaultsManagementViewModel.clenState();
                });
            }
            if (newState.isLoading()) {
                Platform.runLater(() -> this.getPrincipalController().getRootPane().setCursor(Cursor.WAIT));
            }
            if (newState.isLoaded()) {
                Platform.runLater(() -> this.getPrincipalController().getRootPane().setCursor(Cursor.DEFAULT));
            }
        });
    }

    @FXML
    private void doDelete() {
        vaultsManagementViewModel.doDelete(cmbDeleteMyVaults.getValue());
    }

    @FXML
    private void openMyVault() {
        vaultsManagementViewModel.openMyVault(cmbOpenMyVaults.getValue(), txtPasswordMyVault.getText());
    }

    @FXML
    private void openOtherUserVault() {
        vaultsManagementViewModel.openOtherUserVault(txtUsernameOwner.getText(), txtNameVaultOther.getText(), txtPasswordOther.getText());
    }

    @FXML
    private void changePassword() {
        vaultsManagementViewModel.changePassword(cmbChangePassMyVaults.getValue(), txtVaultOldPassword.getText(), txtVaultNewPassword.getText());
    }

    @FXML
    private void createVault() {
        String username = this.getPrincipalController().getUser().getUsername();
        String name = txtNameVaultCreate.getText();
        String password = txtPasswordCreate.getText();
        boolean readByAllInput = this.readByAll.isSelected();
        boolean writeByAllInput = this.writeByAll.isSelected();
        String userPassword = this.getPrincipalController().getUser().getPassword();
        vaultsManagementViewModel.createVault(username, name, password, readByAllInput, writeByAllInput, userPassword);
    }
}
