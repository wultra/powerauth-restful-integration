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
package io.getlime.security.powerauth.app.rest.api.javaee.controller.v3;

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthEncryptionProvider;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Sample controller for a custom activation implementation.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Path("/pa/activation/direct")
@Produces(MediaType.APPLICATION_JSON)
public class CustomActivationController {

    @Inject
    private io.getlime.security.powerauth.rest.api.jaxrs.service.v3.ActivationService activationServiceV3;

    @Inject
    private PowerAuthEncryptionProvider encryptionProvider;

    @Context
    private HttpServletRequest httpServletRequest;

    /**
     * Sample custom activation implementation for version 3 of activations. In version 3 the default implementation
     * can be reused by implementing a custom activation provider which handles the logic during the activation.
     *
     * @return ECIES encrypted response.
     * @throws PowerAuthActivationException In case activation fails.
     */
    @POST
    @Path("v3/create")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public EciesEncryptedResponse createActivationV3() throws PowerAuthActivationException {
        try {
            PowerAuthEciesEncryption<ActivationLayer1Request> eciesEncryption = encryptionProvider.decryptRequest(httpServletRequest, ActivationLayer1Request.class, EciesScope.APPLICATION_SCOPE);
            ActivationLayer1Request layer1Request = eciesEncryption.getRequestObject();
            ActivationLayer1Response layer1Response = activationServiceV3.createActivation(layer1Request, eciesEncryption);
            return encryptionProvider.encryptResponse(layer1Response, eciesEncryption);
        } catch (PowerAuthEncryptionException ex) {
            throw new PowerAuthActivationException();
        }
    }

}
