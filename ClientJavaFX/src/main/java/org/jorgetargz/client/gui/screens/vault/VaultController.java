package org.jorgetargz.client.gui.screens.vault;

import io.github.palexdev.materialfx.controls.MFXComboBox;
import io.github.palexdev.materialfx.controls.MFXTextField;
import jakarta.inject.Inject;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.Cursor;
import javafx.scene.control.Alert;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.client.gui.screens.common.BaseScreenController;
import org.jorgetargz.client.gui.screens.common.ScreenConstants;
import org.jorgetargz.utils.modelo.Message;

@Log4j2
public class VaultController extends BaseScreenController {

    private final VaultsViewModel vaultsViewModel;
    @FXML
    private MFXTextField txtMessageSave;
    @FXML
    private MFXTextField txtMessageUpdate;
    @FXML
    private MFXComboBox<Message> cmbMessages;
    @FXML
    private MFXTextField txtUsernameToShare;

    @FXML
    private TableView<Message> tableMessages;
    @FXML
    private TableColumn<Message, Integer> columnId;
    @FXML
    private TableColumn<Message, String> columnContent;

    @Inject
    public VaultController(VaultsViewModel vaultsViewModel) {
        this.vaultsViewModel = vaultsViewModel;
    }

    public void initialize() {

        columnId.setCellValueFactory(new PropertyValueFactory<>(ScreenConstants.ID));
        columnContent.setCellValueFactory(new PropertyValueFactory<>(ScreenConstants.CONTENT_UNSECURED));
        vaultsViewModel.getState().addListener((observableValue, oldState, newState) -> {
            if (newState.error() != null) {
                Platform.runLater(() -> {
                    this.getPrincipalController().showAlert(Alert.AlertType.ERROR, ScreenConstants.ERROR, newState.error());
                    vaultsViewModel.clenState();
                });
            }
            if (newState.messages() != null) {
                Platform.runLater(() -> {
                    tableMessages.getItems().setAll(newState.messages());
                    cmbMessages.getItems().setAll(newState.messages());
                });
            }
            if (newState.operationDone()) {
                Platform.runLater(() -> {
                    this.getPrincipalController().showAlert(Alert.AlertType.INFORMATION, ScreenConstants.SUCCESS, ScreenConstants.OPERATION_DONE);
                    vaultsViewModel.clenState();
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

    @Override
    public void principalCargado() {
        vaultsViewModel.loadMessages(getPrincipalController().getVault());
    }

    @FXML
    private void saveMessage() {
        vaultsViewModel.saveMessage(getPrincipalController().getVault(), txtMessageSave.getText());
    }

    @FXML
    private void updateMessage() {
        Message message = tableMessages.getSelectionModel().getSelectedItem();
        vaultsViewModel.updateMessage(getPrincipalController().getVault(), message, txtMessageUpdate.getText());
    }

    @FXML
    private void deleteMessage() {
        vaultsViewModel.deleteMessage(getPrincipalController().getVault(), cmbMessages.getValue());
    }

    @FXML
    private void updateMessageField() {
        Message message = tableMessages.getSelectionModel().getSelectedItem();
        txtMessageUpdate.setText(message.getContentUnsecured());
    }


    @FXML
    private void share() {
        String userToShare = txtUsernameToShare.getText();
        vaultsViewModel.share(getPrincipalController().getVault(), userToShare);
    }
}
