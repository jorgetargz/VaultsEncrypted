package org.jorgetargz.client.gui.screens.welcome;

import javafx.animation.Interpolator;
import javafx.animation.TranslateTransition;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.util.Duration;
import org.jorgetargz.client.gui.screens.common.BaseScreenController;
import org.jorgetargz.client.gui.screens.common.ScreenConstants;
import org.jorgetargz.utils.modelo.User;

public class WelcomeScreenController extends BaseScreenController {


    @FXML
    private Label lbBienvenido;


    private void animarPantalla() {
        TranslateTransition translate = new TranslateTransition();
        translate.setNode(lbBienvenido);
        translate.setDuration(Duration.millis(1000));
        translate.setCycleCount(1);
        translate.setInterpolator(Interpolator.LINEAR);
        translate.setFromX(getPrincipalController().getWidth());
        translate.setToX(lbBienvenido.getLayoutX());
        translate.play();
    }

    @Override
    public void principalCargado() {
        User user = getPrincipalController().getUser();
        String welcome = ScreenConstants.WELCOME_MESSAGE + user.getUsername();
        lbBienvenido.setText(welcome);
        animarPantalla();
    }

}
