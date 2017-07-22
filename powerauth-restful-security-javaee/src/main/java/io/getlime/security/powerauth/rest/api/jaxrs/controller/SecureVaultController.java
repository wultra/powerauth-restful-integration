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

import com.google.common.io.BaseEncoding;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.powerauth.soap.PowerAuthPortServiceStub;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.model.response.VaultUnlockResponse;
import io.getlime.security.powerauth.soap.axis.client.PowerAuthServiceClient;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.io.UnsupportedEncodingException;
import java.util.Map;

/**
 * Controller implementing secure vault related end-points from the
 * PowerAuth Standard API.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Path("pa/vault")
@Produces(MediaType.APPLICATION_JSON)
public class SecureVaultController {

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    /**
     * Request the vault unlock key.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @return PowerAuth RESTful response with {@link VaultUnlockResponse} payload.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     * @throws UnsupportedEncodingException In case UTF-8 is not supported.
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("unlock")
    public ObjectResponse<VaultUnlockResponse> unlockVault(@HeaderParam(PowerAuthHttpHeader.HEADER_NAME) String signatureHeader) throws PowerAuthAuthenticationException, PowerAuthSecureVaultException {
        try {
            Map<String, String> map = PowerAuthHttpHeader.parsePowerAuthSignatureHTTPHeader(signatureHeader);
            String activationId = map.get(PowerAuthHttpHeader.ACTIVATION_ID);
            String applicationId = map.get(PowerAuthHttpHeader.APPLICATION_ID);
            String signature = map.get(PowerAuthHttpHeader.SIGNATURE);
            String signatureType = map.get(PowerAuthHttpHeader.SIGNATURE_TYPE);
            String nonce = map.get(PowerAuthHttpHeader.NONCE);

            String data = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", BaseEncoding.base64().decode(nonce), null);

            PowerAuthPortServiceStub.VaultUnlockResponse soapResponse = powerAuthClient.unlockVault(activationId, applicationId, data, signature, signatureType);

            if (!soapResponse.getSignatureValid()) {
                throw new PowerAuthAuthenticationException();
            }

            VaultUnlockResponse response = new VaultUnlockResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setEncryptedVaultEncryptionKey(soapResponse.getEncryptedVaultEncryptionKey());

            return new ObjectResponse<>(response);
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PowerAuthSecureVaultException();
        }
    }

}
