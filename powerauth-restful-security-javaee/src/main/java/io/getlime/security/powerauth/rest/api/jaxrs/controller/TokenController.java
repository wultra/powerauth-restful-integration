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
import io.getlime.security.powerauth.rest.api.jaxrs.converter.SignatureTypeConverter;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.model.request.TokenCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.TokenRemoveRequest;
import io.getlime.security.powerauth.rest.api.model.response.TokenCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.TokenRemoveResponse;
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

    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("create")
    public ObjectResponse<TokenCreateResponse> createToken(ObjectRequest<TokenCreateRequest> request, @HeaderParam(PowerAuthTokenHttpHeader.HEADER_NAME) String tokenHeader) throws RemoteException, PowerAuthAuthenticationException {

        try {

            PowerAuthApiAuthentication authentication = authenticationProvider.validateToken(tokenHeader, Arrays.asList(
                    PowerAuthSignatureTypes.POSSESSION,
                    PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
                    PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
                    PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
            ));

            if (authentication != null && authentication.getActivationId() != null) {

                // Fetch activation ID and signature type
                final String activationId = authentication.getActivationId();
                final PowerAuthSignatureTypes signatureFactors = authentication.getSignatureFactors();

                // Fetch data from the request
                final TokenCreateRequest requestObject = request.getRequestObject();
                final String ephemeralPublicKey = requestObject.getEphemeralPublicKey();

                // Prepare a signature type converter
                SignatureTypeConverter converter = new SignatureTypeConverter();

                // Create a token
                final PowerAuthPortServiceStub.CreateTokenResponse token = powerAuthClient.createToken(activationId, ephemeralPublicKey, converter.convertFrom(signatureFactors));

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

    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("remove")
    public ObjectResponse<TokenRemoveResponse> removeToken(ObjectRequest<TokenRemoveRequest> request, @HeaderParam(PowerAuthTokenHttpHeader.HEADER_NAME) String tokenHeader) throws RemoteException, PowerAuthAuthenticationException {

        try {

            PowerAuthApiAuthentication authentication = authenticationProvider.validateToken(tokenHeader, Arrays.asList(
                    PowerAuthSignatureTypes.POSSESSION,
                    PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
                    PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
                    PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
            ));

            if (authentication != null && authentication.getActivationId() != null) {

                // Fetch activation ID
                final String activationId = authentication.getActivationId();

                // Fetch token ID from the request
                final TokenRemoveRequest requestObject = request.getRequestObject();
                final String tokenId = requestObject.getTokenId();

                // Remove a token, ignore response, since the endpoint should quietly return
                powerAuthClient.removeToken(tokenId, activationId);

                // Prepare a response
                final TokenRemoveResponse responseObject = new TokenRemoveResponse();
                responseObject.setTokenId(requestObject.getTokenId());
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
