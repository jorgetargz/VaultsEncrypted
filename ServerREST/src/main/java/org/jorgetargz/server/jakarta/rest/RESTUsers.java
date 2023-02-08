package org.jorgetargz.server.jakarta.rest;

import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import org.jorgetargz.server.domain.services.ServicesUsers;
import org.jorgetargz.utils.common.ConstantesAPI;
import org.jorgetargz.utils.modelo.User;

@Path(ConstantesAPI.PATH_USERS)
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class RESTUsers {

    private final ServicesUsers servicesUsers;

    @Context
    SecurityContext securityContext;

    @Inject
    public RESTUsers(ServicesUsers servicesUsers) {
        this.servicesUsers = servicesUsers;
    }

    @GET
    @Path(ConstantesAPI.USERNAME_PATH_PARAM)
    @RolesAllowed({ConstantesAPI.ROLE_ADMIN, ConstantesAPI.ROLE_USER})
    public User get(@PathParam(ConstantesAPI.USERNAME_PARAM) String username) {
        return servicesUsers.scGet(username);
    }

    @POST
    @RolesAllowed(ConstantesAPI.ROLE_ADMIN)
    public Response create(User user) {
        return Response.status(Response.Status.CREATED)
                .entity(servicesUsers.scSave(user))
                .build();
    }

    @DELETE
    @Path(ConstantesAPI.USERNAME_PATH_PARAM)
    @RolesAllowed(ConstantesAPI.ROLE_ADMIN)
    public Response delete(@PathParam(ConstantesAPI.USERNAME_PARAM) String username) {
        servicesUsers.scDelete(username);
        return Response.noContent().build();
    }

}