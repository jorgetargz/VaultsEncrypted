module ServerRest {
    requires Security;
    requires Utils;
    requires lombok;
    requires org.apache.logging.log4j;
    requires com.zaxxer.hikari;
    requires java.sql;
    requires spring.tx;
    requires spring.jdbc;
    requires org.jose4j;
    requires jakarta.jakartaee.web.api;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
}