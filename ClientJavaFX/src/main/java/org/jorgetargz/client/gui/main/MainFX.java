package org.jorgetargz.client.gui.main;

import org.jorgetargz.client.gui.main.common.Constants;
import org.jorgetargz.client.gui.screens.main.MainController;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

import java.io.IOException;
import java.util.Locale;
import java.util.ResourceBundle;

public class MainFX {

    @Inject
    FXMLLoader fxmlLoader;

    public void start(@Observes @StartupScene Stage stage) {
        try {
            ResourceBundle r = ResourceBundle.getBundle(Constants.I_18_N_TEXTS_UI, Locale.ENGLISH);

            fxmlLoader.setResources(r);
            Parent fxmlParent = fxmlLoader.load(getClass().getResourceAsStream(Constants.FXML_MAIN_SCREEN_FXML));
            MainController controller = fxmlLoader.getController();
            controller.setStage(stage);

            Scene scene = new Scene(fxmlParent);
            scene.setFill(Color.TRANSPARENT);
            stage.setScene(scene);
            stage.getScene().getStylesheets().add(getClass().getResource(Constants.CSS_STYLE_CSS).toExternalForm());
            stage.setTitle(r.getString(Constants.APP_TITLE));
            stage.initStyle(StageStyle.TRANSPARENT);
            stage.show();
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(0);
        }
    }

}
