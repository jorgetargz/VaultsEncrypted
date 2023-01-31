package org.jorgetargz.server.jakarta.rest;

import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.jorgetargz.server.domain.services.ServicesUsers;
import org.jorgetargz.server.jakarta.common.Constantes;
import org.jorgetargz.utils.common.ConstantesAPI;
import org.jorgetargz.utils.modelo.BaseError;

import java.time.LocalDateTime;

@Path(ConstantesAPI.PATH_LOGIN)
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class RESTLogin {

    private final ServicesUsers servicesUsers;

    @Context
    private HttpServletRequest httpRequest;

    @Context
    SecurityContext securityContext;

    @Inject
    public RESTLogin(ServicesUsers servicesUsers) {
        this.servicesUsers = servicesUsers;
    }

    @GET
    public Response login() {
        if (securityContext.getUserPrincipal() != null) {
            return Response.ok()
                    .entity(servicesUsers.scGet(securityContext.getUserPrincipal().getName()))
                    .build();
        } else {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new BaseError((String) httpRequest.getAttribute(Constantes.ERROR_LOGIN), LocalDateTime.now()))
                    .build();
        }
    }

    @GET
    @RolesAllowed({ConstantesAPI.ROLE_ADMIN, ConstantesAPI.ROLE_USER})
    @Path(ConstantesAPI.LOGOUT_PATH)
    public Response logout(@HeaderParam(HttpHeaders.AUTHORIZATION) String authorization) {
        if (securityContext.getUserPrincipal() != null) {
            servicesUsers.scLogout(authorization);
            return Response.noContent().build();
        } else {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new BaseError((String) httpRequest.getAttribute(Constantes.ERROR_LOGIN), LocalDateTime.now()))
                    .build();
        }
    }

}