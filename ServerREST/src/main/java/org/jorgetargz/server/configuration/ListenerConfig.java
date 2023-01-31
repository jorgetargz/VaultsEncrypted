package org.jorgetargz.server.configuration;

import org.jorgetargz.server.dao.DBConnection;
import jakarta.inject.Inject;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;

@WebListener()
public class ListenerConfig implements ServletContextListener {

    private final DBConnection pool;

    @Inject
    public ListenerConfig(DBConnection pool) {
        this.pool = pool;
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
      /* This method is invoked when the Servlet Context
         (the Web application) is undeployed or
         Application Server shuts down.
      */
        pool.closePool();
    }
}