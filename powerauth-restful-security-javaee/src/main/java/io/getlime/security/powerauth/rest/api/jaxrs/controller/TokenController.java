/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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

package io.getlime.security.powerauth.rest.api.jaxrs.controller;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.powerauth.soap.PowerAuthPortServiceStub;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.model.request.TokenCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.TokenCreateResponse;
import io.getlime.security.powerauth.soap.axis.client.PowerAuthServiceClient;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.rmi.RemoteException;
import java.util.Arrays;

/**
 * Controller responsible for publishing services related to simple token-based authentication.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Path("pa/token")
@Produces(MediaType.APPLICATION_JSON)
public class TokenController {

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @Context
    private HttpServletRequest httpServletRequest;

    // TODO: We should isolate this method to some one place in SOAP client, so that we do not need to rely on it here.
    private PowerAuthPortServiceStub.SignatureType convertTo(PowerAuthSignatureTypes powerAuthSignatureTypes) {
        switch (powerAuthSignatureTypes) {
            case POSSESSION:
                return PowerAuthPortServiceStub.SignatureType.POSSESSION;
            case KNOWLEDGE:
                return PowerAuthPortServiceStub.SignatureType.KNOWLEDGE;
            case BIOMETRY:
                return PowerAuthPortServiceStub.SignatureType.BIOMETRY;
            case POSSESSION_KNOWLEDGE:
                return PowerAuthPortServiceStub.SignatureType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY:
                return PowerAuthPortServiceStub.SignatureType.POSSESSION_BIOMETRY;
            default:
                return PowerAuthPortServiceStub.SignatureType.POSSESSION_KNOWLEDGE_BIOMETRY;
        }
    }

    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("create")
    public ObjectResponse<TokenCreateResponse> createToken(ObjectRequest<TokenCreateRequest> request, @HeaderParam(PowerAuthTokenHttpHeader.HEADER_NAME) String tokenHeader) throws RemoteException, PowerAuthAuthenticationException {

        try {

            PowerAuthApiAuthentication authentication = authenticationProvider.validateToken(tokenHeader, Arrays.asList(
                    PowerAuthSignatureTypes.POSSESSION,
                    PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
                    PowerAuthSignatureTypes.POSSESSION_BIOMETRY
            ));

            if (authentication != null && authentication.getActivationId() != null) {

                // Fetch activation ID and signature type
                final String activationId = authentication.getActivationId();
                final PowerAuthSignatureTypes signatureFactors = authentication.getSignatureFactors();

                // Fetch data from the request
                final TokenCreateRequest requestObject = request.getRequestObject();
                final String ephemeralPublicKey = requestObject.getEphemeralPublicKey();

                // Create a token
                final PowerAuthPortServiceStub.CreateTokenResponse token = powerAuthClient.createToken(activationId, ephemeralPublicKey, convertTo(signatureFactors));

                // Prepare a response
                final TokenCreateResponse responseObject = new TokenCreateResponse();
                responseObject.setMac(token.getMac());
                responseObject.setEncryptedData(token.getEncryptedData());
                return new ObjectResponse<>(responseObject);
            } else {
                throw new PowerAuthAuthenticationException();
            }
        }  catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PowerAuthAuthenticationException(ex.getMessage());
        }

    }

}
