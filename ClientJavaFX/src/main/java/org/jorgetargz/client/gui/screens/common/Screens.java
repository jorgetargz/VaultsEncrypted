package org.jorgetargz.client.gui.screens.common;

public enum Screens {

    WELCOME(ScreenConstants.FXML_WELCOME_SCREEN_FXML),
    LOGIN(ScreenConstants.FXML_LOGIN_SCREEN_FXML),
    USER_MANAGEMENT(ScreenConstants.FXML_USERS_MANAGEMENT_SCREEN_FXML),
    VAULT_MANAGEMENT(ScreenConstants.FXML_VAULTS_MANAGEMENT_SCREEN_FXML),
    VAULT(ScreenConstants.FXML_VAULT_SCREEN_FXML);

    private final String path;

    Screens(String path) {
        this.path = path;
    }

    public String getPath() {
        return path;
    }


}
