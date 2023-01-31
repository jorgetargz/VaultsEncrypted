module Security {
    requires com.google.common;
    requires lombok;
    requires org.apache.logging.log4j;
    requires Utils;

    exports org.jorgetargz.security;
    exports org.jorgetargz.security.impl;
}
