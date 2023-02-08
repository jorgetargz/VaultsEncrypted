package org.jorgetargz.server.jakarta.rest;


import jakarta.annotation.security.DeclareRoles;
import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jorgetargz.utils.common.ConstantesAPI;

import java.security.Security;

@ApplicationPath(ConstantesAPI.API_PATH)
@DeclareRoles({ConstantesAPI.ROLE_ADMIN, ConstantesAPI.ROLE_USER})
public class JAXRSApplication extends Application {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}
