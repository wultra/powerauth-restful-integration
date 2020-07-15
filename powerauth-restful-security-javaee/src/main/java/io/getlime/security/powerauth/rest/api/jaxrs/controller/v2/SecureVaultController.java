/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2018 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package io.getlime.security.powerauth.rest.api.jaxrs.controller.v2;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.jaxrs.service.v2.SecureVaultService;
import io.getlime.security.powerauth.rest.api.model.request.v2.VaultUnlockRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.VaultUnlockResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

/**
 * Controller implementing secure vault related end-points from the
 * PowerAuth Standard API.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Path("pa/vault")
@Produces(MediaType.APPLICATION_JSON)
public class SecureVaultController {

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultController.class);

    @Inject
    private SecureVaultService secureVaultServiceV2;

    @Inject
    private HttpServletRequest httpServletRequest;

    /**
     * Request the vault unlock key.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @param request Vault unlock request data.
     * @return PowerAuth RESTful response with {@link VaultUnlockResponse} payload.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     * @throws PowerAuthSecureVaultException In case unlocking the vault fails.
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("unlock")
    public ObjectResponse<VaultUnlockResponse> unlockVault(@HeaderParam(PowerAuthSignatureHttpHeader.HEADER_NAME) String signatureHeader,
                                                           ObjectRequest<VaultUnlockRequest> request) throws PowerAuthAuthenticationException, PowerAuthSecureVaultException {
        // Request object is not validated - it is optional for version 2

        // Parse the header
        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(signatureHeader);

        // Validate the header
        try {
            PowerAuthSignatureHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Signature validation failed, error: {}", ex.getMessage());
            throw new PowerAuthAuthenticationException();
        }

        if (!"2.0".equals(header.getVersion()) && !"2.1".equals(header.getVersion())) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", header.getVersion());
            throw new PowerAuthAuthenticationException();
        }

        return new ObjectResponse<>(secureVaultServiceV2.vaultUnlock(signatureHeader, request.getRequestObject(), httpServletRequest));
    }

}
