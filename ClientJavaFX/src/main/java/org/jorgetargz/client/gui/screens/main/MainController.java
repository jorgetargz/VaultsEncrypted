package org.jorgetargz.client.gui.screens.main;


import io.github.palexdev.materialfx.font.MFXFontIcon;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import javafx.application.Platform;
import javafx.css.PseudoClass;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.Alert;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.client.gui.screens.common.BaseScreenController;
import org.jorgetargz.client.gui.screens.common.ScreenConstants;
import org.jorgetargz.client.gui.screens.common.Screens;
import org.jorgetargz.utils.common.ConstantesAPI;
import org.jorgetargz.utils.modelo.User;
import org.jorgetargz.utils.modelo.Vault;

import java.io.IOException;
import java.util.Locale;
import java.util.ResourceBundle;

@Log4j2
public class MainController {

    final Instance<Object> instance;
    private final Alert alert;
    private Stage primaryStage;
    private double xOffset;
    private double yOffset;
    @FXML
    private BorderPane root;
    @FXML
    private HBox windowHeader;
    @FXML
    private MFXFontIcon closeIcon;
    @FXML
    private MFXFontIcon minimizeIcon;
    @FXML
    private MFXFontIcon alwaysOnTopIcon;
    @FXML
    public MenuBar menuPrincipal;
    @FXML
    private Menu menuUsers;
    @FXML
    private Menu menuVaults;

    private User user;
    private Vault vault;

    private final MainViewModel mainViewModel;

    @Inject
    public MainController(Instance<Object> instance, MainViewModel mainViewModel) {
        this.instance = instance;
        this.mainViewModel = mainViewModel;
        alert = new Alert(Alert.AlertType.NONE);
    }

    public User getUser() {
        return user;
    }

    public Vault getVault() {
        return vault;
    }

    public BorderPane getRootPane() {
        return root;
    }

    public void setUser(User user) {
        this.user = user;
        if (user.getRole().equals(ConstantesAPI.ROLE_ADMIN)) {
            menuUsers.setVisible(true);
            menuVaults.setVisible(false);
        } else {
            menuUsers.setVisible(false);
            menuVaults.setVisible(true);
        }
    }

    public void setStage(Stage stage) {
        primaryStage = stage;
    }

    public void initialize() {
        loadWindow();

        menuPrincipal.setVisible(false);
        cargarPantalla(Screens.LOGIN);

        mainViewModel.getState().addListener((observable, oldValue, newValue) -> {
            if (newValue.onLogout()) {
                Platform.runLater(() -> {
                    showAlert(Alert.AlertType.INFORMATION, ScreenConstants.INFORMATION, ScreenConstants.LOGOUT_SUCCESS);
                    user = null;
                    menuPrincipal.setVisible(false);
                    mainViewModel.clearState();
                    cargarPantalla(Screens.LOGIN);
                });
            }
            if (newValue.error() != null) {
                Platform.runLater(() -> showAlert(Alert.AlertType.ERROR, ScreenConstants.ERROR, newValue.error()));
            }
        });
    }

    private void loadWindow() {
        closeIcon.addEventHandler(MouseEvent.MOUSE_CLICKED, event -> mainViewModel.doExit());
        minimizeIcon.addEventHandler(MouseEvent.MOUSE_CLICKED, event -> ((Stage) root.getScene().getWindow()).setIconified(true));
        alwaysOnTopIcon.addEventHandler(MouseEvent.MOUSE_CLICKED, event -> {
            boolean newVal = !primaryStage.isAlwaysOnTop();
            alwaysOnTopIcon.pseudoClassStateChanged(PseudoClass
                    .getPseudoClass(ScreenConstants.ALWAYS_ON_TOP), newVal);
            primaryStage.setAlwaysOnTop(newVal);
        });

        windowHeader.setOnMousePressed(event -> {
            xOffset = primaryStage.getX() - event.getScreenX();
            yOffset = primaryStage.getY() - event.getScreenY();
        });
        windowHeader.setOnMouseDragged(event -> {
            primaryStage.setX(event.getScreenX() + xOffset);
            primaryStage.setY(event.getScreenY() + yOffset);
        });
    }

    public double getWidth() {
        return root.getScene().getWindow().getWidth();
    }

    public void showAlert(Alert.AlertType alertType, String titulo, String mensaje) {
        alert.setAlertType(alertType);
        alert.setTitle(titulo);
        alert.setHeaderText(titulo);
        alert.setContentText(mensaje);
        alert.showAndWait();
    }

    private void cargarPantalla(Screens pantalla) {
        Pane panePantalla;
        ResourceBundle r = ResourceBundle.getBundle(ScreenConstants.I_18_N_TEXTS_UI, Locale.ENGLISH);
        try {
            FXMLLoader fxmlLoader = new FXMLLoader();
            fxmlLoader.setControllerFactory(controller -> instance.select(controller).get());
            fxmlLoader.setResources(r);
            panePantalla = fxmlLoader.load(getClass().getResourceAsStream(pantalla.getPath()));
            BaseScreenController pantallaController = fxmlLoader.getController();
            pantallaController.setPrincipalController(this);
            pantallaController.principalCargado();
            root.setCenter(panePantalla);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }

    @FXML
    private void menuOnClick(ActionEvent actionEvent) {
        switch (((MenuItem) actionEvent.getSource()).getId()) {
            case ScreenConstants.MENU_ITEM_PANTALLA_USERS_MANAGEMENT -> cargarPantalla(Screens.USER_MANAGEMENT);
            case ScreenConstants.MENU_ITEM_PANTALLA_VAULTS_MANAGEMENT -> cargarPantalla(Screens.VAULT_MANAGEMENT);
            default -> cargarPantalla(Screens.WELCOME);
        }
    }

    @FXML
    private void cambiarcss() {
        if (primaryStage.getScene().getRoot().getStylesheets().stream().findFirst().isEmpty()
                || (primaryStage.getScene().getRoot().getStylesheets().stream().findFirst().isPresent()
                && primaryStage.getScene().getRoot().getStylesheets().stream().findFirst().get().contains(ScreenConstants.STYLE))) {
            try {
                primaryStage.getScene().getRoot().getStylesheets().clear();
                primaryStage.getScene().getRoot().getStylesheets().add(getClass().getResource(ScreenConstants.CSS_DARKMODE_CSS).toExternalForm());
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        } else {
            try {
                primaryStage.getScene().getRoot().getStylesheets().clear();
                primaryStage.getScene().getRoot().getStylesheets().add(getClass().getResource(ScreenConstants.CSS_STYLE_CSS).toExternalForm());
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        }
    }

    @FXML
    private void acercaDe() {
        showAlert(Alert.AlertType.INFORMATION, ScreenConstants.ABOUT, ScreenConstants.AUTHOR_DATA);
    }

    @FXML
    private void logout() {
        mainViewModel.doLogout();
    }

    @FXML
    private void exit() {
        mainViewModel.doExit();
    }

    public void onLoginDone() {
        menuPrincipal.setVisible(true);
        cargarPantalla(Screens.WELCOME);
    }

    public void onVaultOpened(Vault vault) {
        this.vault = vault;
        cargarPantalla(Screens.VAULT);
    }

}