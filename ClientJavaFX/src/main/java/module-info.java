module ClientJavaFX {
    requires Utils;
    requires Security;

    requires org.apache.commons.lang3;

    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;

    requires javafx.graphics;
    requires javafx.controls;
    requires javafx.fxml;
    requires MaterialFX;

    requires retrofit2;
    requires retrofit2.converter.gson;
    requires retrofit2.converter.scalars;
    requires retrofit2.adapter.rxjava3;
    requires io.reactivex.rxjava3;

    requires lombok;
    requires io.vavr;
    requires org.apache.logging.log4j;

    requires java.sql;
    requires gson;
    requires okhttp3;
    requires jakarta.cdi;
    requires jakarta.inject;
    requires jakarta.el;
    requires com.nimbusds.jose.jwt;

    exports org.jorgetargz.client.dao;
    exports org.jorgetargz.client.dao.di;
    exports org.jorgetargz.client.dao.impl;
    exports org.jorgetargz.client.dao.vault_api;
    exports org.jorgetargz.client.dao.vault_api.utils;
    exports org.jorgetargz.client.dao.common;
    exports org.jorgetargz.client.dao.vault_api.di;
    exports org.jorgetargz.client.dao.vault_api.config;
    exports org.jorgetargz.client.domain.services;
    exports org.jorgetargz.client.domain.services.impl;
    exports org.jorgetargz.client.domain.services.utils;

    exports org.jorgetargz.client.gui.main.common;
    exports org.jorgetargz.client.gui.screens.welcome;
    exports org.jorgetargz.client.gui.screens.login;
    exports org.jorgetargz.client.gui.screens.main;
    exports org.jorgetargz.client.gui.screens.users_management;
    exports org.jorgetargz.client.gui.screens.vault_management;
    exports org.jorgetargz.client.gui.screens.vault;

    exports org.jorgetargz.client.utils;

    opens config;
    opens org.jorgetargz.client.dao.common;
    opens org.jorgetargz.client.domain.common;
    opens org.jorgetargz.client.gui.screens.vault;

    opens org.jorgetargz.client.gui.main;
    opens org.jorgetargz.client.gui.main.common;
    opens org.jorgetargz.client.gui.screens.common;
    opens org.jorgetargz.client.gui.screens.main;
    opens org.jorgetargz.client.gui.screens.login;
    opens org.jorgetargz.client.gui.screens.welcome;
    opens org.jorgetargz.client.gui.screens.users_management;
    opens org.jorgetargz.client.gui.screens.vault_management;

}