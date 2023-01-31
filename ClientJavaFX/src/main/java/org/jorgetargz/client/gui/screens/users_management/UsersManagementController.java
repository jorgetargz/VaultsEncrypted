package org.jorgetargz.client.gui.screens.users_management;

import io.github.palexdev.materialfx.controls.MFXPasswordField;
import io.github.palexdev.materialfx.controls.MFXTextField;
import jakarta.inject.Inject;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.Cursor;
import javafx.scene.control.Alert;
import javafx.scene.control.Label;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.client.gui.screens.common.BaseScreenController;
import org.jorgetargz.client.gui.screens.common.ScreenConstants;

@Log4j2
public class UsersManagementController extends BaseScreenController {

    private final UsersManagementViewModel usersManagementViewModel;
    @FXML
    private MFXTextField txtUsernameRegister;
    @FXML
    private MFXPasswordField txtPasswordRegister;
    @FXML
    private MFXTextField txtUsernameDelete;

    @Inject
    public UsersManagementController(UsersManagementViewModel usersManagementViewModel) {
        this.usersManagementViewModel = usersManagementViewModel;
    }

    public void initialize() {
        usersManagementViewModel.getState().addListener((observableValue, oldState, newState) -> {
            if (newState.error() != null) {
                Platform.runLater(() -> {
                    this.getPrincipalController().showAlert(Alert.AlertType.ERROR, ScreenConstants.ERROR, newState.error());
                    usersManagementViewModel.clenState();
                });
            }
            if (newState.operationDone()) {
                Platform.runLater(() -> {
                    this.getPrincipalController().showAlert(Alert.AlertType.INFORMATION, ScreenConstants.SUCCESS, ScreenConstants.OPERATION_DONE);
                    usersManagementViewModel.clenState();
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
    private void doRegister() {
        usersManagementViewModel.doRegister(txtUsernameRegister.getText(), txtPasswordRegister.getText());
    }

    @FXML
    private void doDelete() {
        usersManagementViewModel.doDelete(txtUsernameDelete.getText());
    }
}
