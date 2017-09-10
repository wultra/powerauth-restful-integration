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
package io.getlime.security.powerauth.rest.api.spring.provider;

import com.google.common.io.BaseEncoding;
import io.getlime.powerauth.soap.SignatureType;
import io.getlime.powerauth.soap.VerifySignatureRequest;
import io.getlime.powerauth.soap.VerifySignatureResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.base.application.PowerAuthApplicationConfiguration;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.provider.PowerAuthAuthenticationProviderBase;
import io.getlime.security.powerauth.rest.api.base.validator.PowerAuthHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthenticationImpl;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthAuthenticationImpl;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Implementation of PowerAuth authentication provider.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
@Component
public class PowerAuthAuthenticationProvider extends PowerAuthAuthenticationProviderBase implements AuthenticationProvider {

    private PowerAuthServiceClient powerAuthClient;

    private PowerAuthApplicationConfiguration applicationConfiguration;

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired(required=false)
    public void setApplicationConfiguration(PowerAuthApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        PowerAuthAuthenticationImpl powerAuthAuthentication = (PowerAuthAuthenticationImpl) authentication;

        if (powerAuthAuthentication.getSignatureType() != null) {

            final String signatureTypeSanitized = powerAuthAuthentication.getSignatureType().toUpperCase();
            final SignatureType signatureType = SignatureType.fromValue(signatureTypeSanitized);

            VerifySignatureRequest soapRequest = new VerifySignatureRequest();
            soapRequest.setActivationId(powerAuthAuthentication.getActivationId());
            soapRequest.setApplicationKey(powerAuthAuthentication.getApplicationKey());
            soapRequest.setSignature(powerAuthAuthentication.getSignature());
            soapRequest.setSignatureType(signatureType);
            soapRequest.setData(PowerAuthHttpBody.getSignatureBaseString(
                    powerAuthAuthentication.getHttpMethod(),
                    powerAuthAuthentication.getRequestUri(),
                    powerAuthAuthentication.getNonce(),
                    powerAuthAuthentication.getData()
            ));

            VerifySignatureResponse soapResponse = powerAuthClient.verifySignature(soapRequest);

            if (soapResponse.isSignatureValid()) {
                PowerAuthApiAuthenticationImpl apiAuthentication = new PowerAuthApiAuthenticationImpl();
                apiAuthentication.setActivationId(soapResponse.getActivationId());
                apiAuthentication.setUserId(soapResponse.getUserId());
                apiAuthentication.setApplicationId(soapResponse.getApplicationId());
                apiAuthentication.setSignatureFactors(PowerAuthSignatureTypes.getEnumFromString(soapResponse.getSignatureType().value()));
                apiAuthentication.setAuthenticated(true);
                return apiAuthentication;
            } else {
                return null;
            }

        } else {
            return null;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == PowerAuthAuthenticationImpl.class;
    }

    /**
     * Validate the signature from the PowerAuth 2.0 HTTP header against the provided HTTP method, request body and URI identifier.
     * Make sure to accept only allowed signatures.
     * @param httpMethod HTTP method (GET, POST, ...)
     * @param httpBody Body of the HTTP request.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth 2.0 HTTP authorization header.
     * @param allowedSignatureTypes Allowed types of the signature.
     * @return Instance of a PowerAuthApiAuthenticationImpl on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthentication validateRequestSignature(
            String httpMethod,
            byte[] httpBody,
            String requestUriIdentifier,
            String httpAuthorizationHeader,
            List<PowerAuthSignatureTypes> allowedSignatureTypes
    ) throws PowerAuthAuthenticationException {

        // Check for HTTP PowerAuth signature header
        if (httpAuthorizationHeader == null || httpAuthorizationHeader.equals("undefined")) {
            throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_INVALID_EMPTY");
        }

        // Parse HTTP header
        PowerAuthHttpHeader header = PowerAuthHttpHeader.fromValue(httpAuthorizationHeader);

        // Validate the header
        PowerAuthHttpHeaderValidator.validate(header);

        // Check if the application is allowed, "true" is the default behavior
        if (applicationConfiguration != null) {
            boolean isApplicationAllowed = applicationConfiguration.isAllowedApplicationKey(header.getApplicationKey());
            if (!isApplicationAllowed) {
                throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_INVALID_APPLICATION_ID");
            }
        }

        // Check if the signature type is allowed
        PowerAuthSignatureTypes expectedSignatureType = PowerAuthSignatureTypes.getEnumFromString(header.getSignatureType());
        if (!allowedSignatureTypes.contains(expectedSignatureType)) {
            throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_TYPE_INVALID");
        }

        // Configure PowerAuth authentication object
        PowerAuthAuthenticationImpl powerAuthAuthentication = new PowerAuthAuthenticationImpl();
        powerAuthAuthentication.setActivationId(header.getActivationId());
        powerAuthAuthentication.setApplicationKey(header.getApplicationKey());
        powerAuthAuthentication.setNonce(BaseEncoding.base64().decode(header.getNonce()));
        powerAuthAuthentication.setSignatureType(header.getSignatureType());
        powerAuthAuthentication.setSignature(header.getSignature());
        powerAuthAuthentication.setHttpMethod(httpMethod);
        powerAuthAuthentication.setRequestUri(requestUriIdentifier);
        powerAuthAuthentication.setData(httpBody);

        // Call the authentication
        PowerAuthApiAuthentication auth = (PowerAuthApiAuthentication) this.authenticate(powerAuthAuthentication);

        // In case authentication is null, throw PowerAuth exception
        if (auth == null) {
            throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_INVALID_VALUE");
        }

        return auth;
    }

}
