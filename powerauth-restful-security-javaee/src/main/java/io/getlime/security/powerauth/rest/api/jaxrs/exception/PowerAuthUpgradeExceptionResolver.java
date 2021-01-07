package io.getlime.security.powerauth.rest.api.jaxrs.exception;

import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthUpgradeException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * Class responsible for PowerAuth Standard RESTful API exception handling for
 * exceptions that are raised during the activation upgrade.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthUpgradeExceptionResolver implements ExceptionMapper<PowerAuthUpgradeException> {

    @Override
    public Response toResponse(PowerAuthUpgradeException ex) {
        return Response
                .status(Response.Status.BAD_REQUEST)
                .entity(new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError()))
                .build();
    }
}
