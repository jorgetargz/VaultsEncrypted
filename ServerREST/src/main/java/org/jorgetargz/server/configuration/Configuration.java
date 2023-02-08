package org.jorgetargz.server.configuration;

import jakarta.inject.Singleton;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.server.configuration.common.Constantes;

import java.util.Properties;

@Singleton
@Getter
@Log4j2
public class Configuration {

    private String url;
    private String user;
    private String password;
    private String driver;

    public Configuration() {
        try {
            Properties properties = new Properties();
            properties.load(getClass().getClassLoader().getResourceAsStream(Constantes.CONFIG_YAML_PATH));
            this.url = properties.getProperty(Constantes.URL);
            this.password = properties.getProperty(Constantes.PASSWORD);
            this.user = properties.getProperty(Constantes.USER);
            this.driver = properties.getProperty(Constantes.DRIVER);
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
        }
    }

}
