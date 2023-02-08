package org.jorgetargz.server.jakarta.exception_mappers;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import org.jorgetargz.server.dao.excepciones.DatabaseException;
import org.jorgetargz.utils.modelo.BaseError;

import java.time.LocalDateTime;

@Provider
public class DatabaseExceptionMapper implements ExceptionMapper<DatabaseException> {

    public Response toResponse(DatabaseException exception) {
        BaseError baseError = new BaseError(exception.getMessage(), LocalDateTime.now());
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(baseError)
                .type(MediaType.APPLICATION_JSON_TYPE).build();
    }
}
