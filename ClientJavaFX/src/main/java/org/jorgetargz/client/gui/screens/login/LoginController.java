package org.jorgetargz.client.gui.screens.login;

import io.github.palexdev.materialfx.controls.MFXPasswordField;
import io.github.palexdev.materialfx.controls.MFXTextField;
import jakarta.inject.Inject;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.Cursor;
import javafx.scene.control.Alert;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.client.gui.screens.common.BaseScreenController;
import org.jorgetargz.client.gui.screens.common.ScreenConstants;

import java.io.IOException;

@Log4j2
public class LoginController extends BaseScreenController {

    private final LoginViewModel loginViewModel;

    @FXML
    private ImageView logo;
    @FXML
    private MFXTextField txtUsername;
    @FXML
    private MFXPasswordField txtPass;

    @Inject
    public LoginController(LoginViewModel loginViewModel) {
        this.loginViewModel = loginViewModel;
    }

    public void initialize() {
        try (var inputStream = getClass().getResourceAsStream(ScreenConstants.MEDIA_LOGO_PNG)) {
            assert inputStream != null;
            Image logoImage = new Image(inputStream);
            logo.setImage(logoImage);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }

        loginViewModel.getState().addListener((observableValue, oldState, newState) -> {
            if (newState.error() != null) {
                Platform.runLater(() -> {
                    this.getPrincipalController().showAlert(Alert.AlertType.ERROR, ScreenConstants.ERROR, newState.error());
                    loginViewModel.clenState();
                });
            }
            if (newState.user() != null) {
                Platform.runLater(() -> {
                    this.getPrincipalController().setUser(newState.user());
                    this.getPrincipalController().onLoginDone();
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
    private void doLogin() {
        String username = txtUsername.getText();
        String password = txtPass.getText();
        loginViewModel.doLogin(username, password);
    }
}
