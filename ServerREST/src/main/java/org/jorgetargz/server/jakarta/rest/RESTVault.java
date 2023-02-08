package org.jorgetargz.server.jakarta.rest;


import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import org.jorgetargz.server.domain.services.ServicesVaults;
import org.jorgetargz.utils.common.ConstantesAPI;
import org.jorgetargz.utils.modelo.Vault;

import java.util.List;

@Path(ConstantesAPI.PATH_VAULTS)
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class RESTVault {

    private final ServicesVaults servicesVaults;

    @Context
    SecurityContext securityContext;

    @Inject
    public RESTVault(ServicesVaults servicesVaults) {
        this.servicesVaults = servicesVaults;
    }

    @GET
    @RolesAllowed(ConstantesAPI.ROLE_USER)
    public List<Vault> getVaults() {
        return servicesVaults.getVaults(securityContext.getUserPrincipal().getName());
    }

    @GET
    @RolesAllowed(ConstantesAPI.ROLE_USER)
    @Path(ConstantesAPI.VAULT_PATH)
    public Vault getVault(
            @QueryParam(ConstantesAPI.VAULT_NAME) String vaultName,
            @QueryParam(ConstantesAPI.USERNAME_OWNER) String usernameOwner
    ) {
        Vault credentials = Vault.builder()
                .name(vaultName)
                .usernameOwner(usernameOwner)
                .build();
        return servicesVaults.getVault(credentials, securityContext.getUserPrincipal().getName());
    }

    @POST
    @RolesAllowed(ConstantesAPI.ROLE_USER)
    public Vault createVault(Vault vault) {
        return servicesVaults.createVault(vault);
    }

    @POST
    @Path(ConstantesAPI.SHARE_PATH)
    @RolesAllowed(ConstantesAPI.ROLE_USER)
    public Vault shareVault(
            Vault vault,
            @QueryParam(ConstantesAPI.USERNAME_PARAM) String username,
            @QueryParam(ConstantesAPI.PASS_ENC_WITH_USER_PUB_KEY_PARAM) String passwordEncWithUserPubKey
    ) {
        return servicesVaults.shareVault(vault, username, passwordEncWithUserPubKey, securityContext.getUserPrincipal().getName());
    }

    @DELETE
    @RolesAllowed(ConstantesAPI.ROLE_USER)
    @Path(ConstantesAPI.VAULT_ID_PATH_PARAM)
    public Response deleteVault(@PathParam(ConstantesAPI.VAULT_ID_PARAM) int vaultId) {
        servicesVaults.deleteVault(vaultId, securityContext.getUserPrincipal().getName());
        return Response.noContent().build();
    }


}