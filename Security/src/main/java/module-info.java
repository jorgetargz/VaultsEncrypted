module Security {
    requires com.google.common;
    requires lombok;
    requires org.apache.logging.log4j;
    requires Utils;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;

    exports org.jorgetargz.security;
    exports org.jorgetargz.security.impl;
}
