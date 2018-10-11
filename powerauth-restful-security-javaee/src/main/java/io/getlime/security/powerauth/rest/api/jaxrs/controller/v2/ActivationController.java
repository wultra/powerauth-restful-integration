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

package io.getlime.security.powerauth.rest.api.jaxrs.controller.v2;

import com.google.common.io.BaseEncoding;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub;
import io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.base.application.PowerAuthApplicationConfiguration;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.filter.PowerAuthRequestFilterBase;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationStatusResponse;
import io.getlime.security.powerauth.soap.axis.client.PowerAuthServiceClient;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
@Path("pa/activation")
@Produces(MediaType.APPLICATION_JSON)
public class ActivationController {

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @Inject
    private PowerAuthApplicationConfiguration applicationConfiguration;

    /**
     * Create a new activation.
     * @param request PowerAuth RESTful request with {@link ActivationCreateRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationCreateResponse} payload.
     * @throws PowerAuthActivationException In case creating activation fails.
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("create")
    public ObjectResponse<ActivationCreateResponse> createActivation(ObjectRequest<ActivationCreateRequest> request) throws PowerAuthActivationException {

        if (request.getRequestObject() == null) {
            throw new PowerAuthActivationException();
        }

        try {

            String activationIDShort = request.getRequestObject().getActivationIdShort();
            String activationNonce = request.getRequestObject().getActivationNonce();
            String cDevicePublicKey = request.getRequestObject().getEncryptedDevicePublicKey();
            String activationName = request.getRequestObject().getActivationName();
            String extras = request.getRequestObject().getExtras();
            String applicationKey = request.getRequestObject().getApplicationKey();
            String applicationSignature = request.getRequestObject().getApplicationSignature();
            String clientEphemeralKey = request.getRequestObject().getEphemeralPublicKey();

            PowerAuthPortV2ServiceStub.PrepareActivationResponse soapResponse = powerAuthClient.v2().prepareActivation(
                    activationIDShort,
                    activationName,
                    activationNonce,
                    clientEphemeralKey,
                    cDevicePublicKey,
                    extras,
                    applicationKey,
                    applicationSignature
            );

            ActivationCreateResponse response = new ActivationCreateResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setActivationNonce(soapResponse.getActivationNonce());
            response.setEncryptedServerPublicKey(soapResponse.getEncryptedServerPublicKey());
            response.setEncryptedServerPublicKeySignature(soapResponse.getEncryptedServerPublicKeySignature());
            response.setEphemeralPublicKey(soapResponse.getEphemeralPublicKey());

            return new ObjectResponse<>(response);

        } catch (Exception e) {
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Get activation status.
     * @param request PowerAuth RESTful request with {@link ActivationStatusRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationStatusResponse} payload.
     * @throws PowerAuthActivationException In case request fails.
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("status")
    public ObjectResponse<ActivationStatusResponse> getActivationStatus(ObjectRequest<ActivationStatusRequest> request) throws PowerAuthActivationException {

        if (request.getRequestObject() == null) {
            throw new PowerAuthActivationException();
        }

        try {
            String activationId = request.getRequestObject().getActivationId();
            PowerAuthPortV3ServiceStub.GetActivationStatusResponse soapResponse = powerAuthClient.getActivationStatus(activationId);
            ActivationStatusResponse response = new ActivationStatusResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setEncryptedStatusBlob(soapResponse.getEncryptedStatusBlob());
            if (applicationConfiguration != null) {
                response.setCustomObject(applicationConfiguration.statusServiceCustomObject());
            }
            return new ObjectResponse<>(response);
        } catch (Exception e) {
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Get activation status.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @return PowerAuth RESTful response with {@link ActivationRemoveResponse} payload.
     * @throws PowerAuthAuthenticationException In case the signature validation fails.
     * @throws PowerAuthActivationException In case remove request fails.
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("remove")
    public ObjectResponse<ActivationRemoveResponse> removeActivation(@HeaderParam(PowerAuthSignatureHttpHeader.HEADER_NAME) String signatureHeader,
                                                                     @Context HttpServletRequest httpServletRequest) throws PowerAuthAuthenticationException, PowerAuthActivationException {
        try {
            String requestBodyString = ((String) httpServletRequest.getAttribute(PowerAuthRequestFilterBase.POWERAUTH_SIGNATURE_BASE_STRING));
            byte[] requestBodyBytes = requestBodyString == null ? null : BaseEncoding.base64().decode(requestBodyString);
            PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestSignature("POST", requestBodyBytes, "/pa/activation/remove", signatureHeader);
            if (apiAuthentication != null && apiAuthentication.getActivationId() != null) {
                PowerAuthPortV3ServiceStub.RemoveActivationResponse soapResponse = powerAuthClient.removeActivation(apiAuthentication.getActivationId());
                ActivationRemoveResponse response = new ActivationRemoveResponse();
                response.setActivationId(soapResponse.getActivationId());
                return new ObjectResponse<>(response);
            } else {
                throw new PowerAuthAuthenticationException("USER_NOT_AUTHENTICATED");
            }
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PowerAuthActivationException();
        }
    }


}
