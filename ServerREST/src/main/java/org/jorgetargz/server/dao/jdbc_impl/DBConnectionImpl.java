package org.jorgetargz.server.dao.jdbc_impl;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.jorgetargz.server.configuration.Configuration;
import org.jorgetargz.server.dao.DBConnection;
import org.jorgetargz.server.dao.common.Constantes;
import jakarta.annotation.PreDestroy;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import lombok.extern.log4j.Log4j2;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

@Log4j2
@Singleton
public class DBConnectionImpl implements DBConnection {

    private final Configuration config;
    private final DataSource hikariDataSource;

    @Inject
    public DBConnectionImpl(Configuration config) {
        this.config = config;
        this.hikariDataSource = getHikariPool();
    }

    private DataSource getHikariPool() {
        HikariConfig hikariConfig = new HikariConfig();
        hikariConfig.setJdbcUrl(config.getUrl());
        hikariConfig.setUsername(config.getUser());
        hikariConfig.setPassword(config.getPassword());
        hikariConfig.setDriverClassName(config.getDriver());
        hikariConfig.setMaximumPoolSize(Constantes.MAX_POOL_SIZE);

        hikariConfig.setIdleTimeout(Constantes.TIMEOUT_MS);
        hikariConfig.setConnectionTimeout(Constantes.TIMEOUT_MS);
        hikariConfig.setMaxLifetime(Constantes.TIMEOUT_MS);
        hikariConfig.addDataSourceProperty(Constantes.CACHE_PREP_STMTS, true);
        hikariConfig.addDataSourceProperty(Constantes.PREP_STMT_CACHE_SIZE, Constantes.CACHE_SIZE);
        hikariConfig.addDataSourceProperty(Constantes.PREP_STMT_CACHE_SQL_LIMIT, Constantes.CACHE_SQL_LIMIT);

        return new HikariDataSource(hikariConfig);
    }

    @Override
    public Connection getConnection() throws SQLException {
        Connection conn = hikariDataSource.getConnection();
        log.info(Constantes.CONNECTION_TO_DATABASE_ESTABLISHED);
        return conn;
    }

    @Override
    public DataSource getDataSource() {
        return hikariDataSource;
    }

    @Override
    @PreDestroy
    public void closePool() {
        log.info(Constantes.CLOSING_CONNECTION_POOL);
        ((HikariDataSource) hikariDataSource).close();
    }

}
