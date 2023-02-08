package org.jorgetargz.client.dao.vault_api.config;

import jakarta.inject.Singleton;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;
import org.jorgetargz.client.dao.common.Constantes;

import java.io.IOException;
import java.util.Properties;

@Getter
@Log4j2
@Singleton
public class ConfigVaultAPI {

    private String baseUrl = null;

    public ConfigVaultAPI() {
        Properties properties = new Properties();
        try {
            properties.load(getClass().getClassLoader().getResourceAsStream(Constantes.CONFIG_VAULT_API_PATH));
            this.baseUrl = (String) properties.get(Constantes.BASE_URL);
            log.info(Constantes.API_BASE_URL, this.baseUrl);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }
}
