package org.jorgetargz.server.jakarta.exception_mappers;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import org.jorgetargz.server.dao.excepciones.UnauthorizedException;
import org.jorgetargz.utils.modelo.BaseError;

import java.time.LocalDateTime;

@Provider
public class UnauthorizedExceptionMapper implements ExceptionMapper<UnauthorizedException> {

    public Response toResponse(UnauthorizedException e) {
        BaseError baseError = new BaseError(e.getMessage(), LocalDateTime.now());
        return Response.status(Response.Status.UNAUTHORIZED).entity(baseError)
                .type(MediaType.APPLICATION_JSON_TYPE).build();
    }
}
