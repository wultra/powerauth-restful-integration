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
package io.getlime.security.powerauth.rest.api.spring.annotation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEnvelopeKey;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesDecryptorParameters;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.base.filter.PowerAuthRequestFilterBase;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthEncryptionProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;

@Component
public class PowerAuthAnnotationInterceptor extends HandlerInterceptorAdapter {

    private static final Logger logger = LoggerFactory.getLogger(HandlerInterceptorAdapter.class);

    private PowerAuthAuthenticationProvider authenticationProvider;
    private PowerAuthEncryptionProvider encryptionProvider;

    private final EciesFactory eciesFactory = new EciesFactory();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public void setAuthenticationProvider(PowerAuthAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Autowired
    public void setEncryptionProvider(PowerAuthEncryptionProvider encryptionProvider) {
        this.encryptionProvider = encryptionProvider;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        // Check if the provided handler is related to handler method.
        // This is to avoid issues with possible CORS requests )in case of
        // incorrect filter mapping) where there are special "pre-flight"
        // requests before the actual requests.
        if (handler instanceof HandlerMethod) {

            HandlerMethod handlerMethod = (HandlerMethod) handler;

            // Obtain annotations
            PowerAuth powerAuthSignatureAnnotation = handlerMethod.getMethodAnnotation(PowerAuth.class);
            PowerAuthToken powerAuthTokenAnnotation = handlerMethod.getMethodAnnotation(PowerAuthToken.class);
            PowerAuthEncryption powerAuthEncryptionAnnotation = handlerMethod.getMethodAnnotation(PowerAuthEncryption.class);

            // Check that either signature or token annotation is active
            if (powerAuthSignatureAnnotation != null && powerAuthTokenAnnotation != null) {
                logger.error("You cannot use both @PowerAuth and @PowerAuthToken on same handler method. We are removing both.");
                powerAuthSignatureAnnotation = null;
                powerAuthTokenAnnotation = null;
            }

            // Resolve @PowerAuth annotation
            if (powerAuthSignatureAnnotation != null) {

                try {
                    PowerAuthApiAuthentication authentication = this.authenticationProvider.validateRequestSignature(
                            request,
                            powerAuthSignatureAnnotation.resourceId(),
                            request.getHeader(PowerAuthSignatureHttpHeader.HEADER_NAME),
                            new ArrayList<>(Arrays.asList(powerAuthSignatureAnnotation.signatureType()))
                    );
                    request.setAttribute(PowerAuth.AUTHENTICATION_OBJECT, authentication);
                } catch (PowerAuthAuthenticationException ex) {
                    // Silently ignore here and make sure authentication object is null
                    request.setAttribute(PowerAuth.AUTHENTICATION_OBJECT, null);
                }

            }

            // Resolve @PowerAuthToken annotation
            if (powerAuthTokenAnnotation != null) {
                try {
                    PowerAuthApiAuthentication authentication = this.authenticationProvider.validateToken(
                            request.getHeader(PowerAuthTokenHttpHeader.HEADER_NAME),
                            new ArrayList<>(Arrays.asList(powerAuthTokenAnnotation.signatureType()))
                    );
                    request.setAttribute(PowerAuth.AUTHENTICATION_OBJECT, authentication);
                } catch (PowerAuthAuthenticationException ex) {
                    // Silently ignore here and make sure authentication object is null
                    request.setAttribute(PowerAuth.AUTHENTICATION_OBJECT, null);
                }
            }

            // Resolve @PowerAuthEncryption annotation
            if (powerAuthEncryptionAnnotation != null) {
                try {
                    PowerAuthEciesEncryption eciesEncryption = decryptRequest(request);
                    request.setAttribute(PowerAuthEncryption.ENCRYPTION_OBJECT, eciesEncryption);
                } catch (PowerAuthEncryptionException ex) {
                    // Silently ignore here and make sure encryption object is null
                    request.setAttribute(PowerAuthEncryption.ENCRYPTION_OBJECT, null);
                }
            }
        }

        return super.preHandle(request, response, handler);
    }

    /**
     * Decrypt HTTP request body and construct object with ECIES data.
     *
     * @param request HTTP request.
     * @return Object with ECIES data.
     * @throws PowerAuthEncryptionException In case request decryption fails.
     */
    private PowerAuthEciesEncryption decryptRequest(HttpServletRequest request) throws PowerAuthEncryptionException {
        // Only POST HTTP method is supported for ECIES
        if (!"POST".equals(request.getMethod())) {
            throw new PowerAuthEncryptionException("Invalid HTTP request");
        }
        // Read ECIES metadata from HTTP header
        final PowerAuthEciesEncryption eciesEncryption = this.encryptionProvider.prepareEciesEncryption(request.getHeader(PowerAuthEncryptionHttpHeader.HEADER_NAME));

        try {
            // Parse ECIES cryptogram from request body
            String requestBodyString = ((String) request.getAttribute(PowerAuthRequestFilterBase.POWERAUTH_SIGNATURE_BASE_STRING));
            if (requestBodyString == null || requestBodyString.isEmpty()) {
                throw new PowerAuthEncryptionException("Invalid HTTP request");
            }
            byte[] requestBodyBytes = BaseEncoding.base64().decode(requestBodyString);
            final EciesEncryptedRequest eciesRequest = objectMapper.readValue(requestBodyBytes, EciesEncryptedRequest.class);

            // Prepare ephemeral public key
            String ephemeralPublicKey = eciesRequest.getEphemeralPublicKey();
            final byte[] ephemeralPublicKeyBytes = BaseEncoding.base64().decode(eciesRequest.getEphemeralPublicKey());
            final byte[] encryptedDataBytes = BaseEncoding.base64().decode(eciesRequest.getEncryptedData());
            final byte[] macBytes = BaseEncoding.base64().decode(eciesRequest.getMac());

            // Obtain ECIES decryptor parameters from PowerAuth server
            final PowerAuthEciesDecryptorParameters decryptorParameters = this.encryptionProvider.getEciesDecryptorParameters(eciesEncryption.getActivationId(),
                    eciesEncryption.getApplicationKey(), ephemeralPublicKey);

            // Prepare envelope key and sharedInfo2 parameter for decryptor
            final byte[] secretKey = BaseEncoding.base64().decode(decryptorParameters.getSecretKey());
            final EciesEnvelopeKey envelopeKey = new EciesEnvelopeKey(secretKey, ephemeralPublicKeyBytes);
            final byte[] sharedInfo2 = BaseEncoding.base64().decode(decryptorParameters.getSharedInfo2());

            // Construct decryptor and set it to the request for later encryption of response
            final EciesDecryptor eciesDecryptor = eciesFactory.getEciesDecryptor(envelopeKey, sharedInfo2);
            eciesEncryption.setEciesDecryptor(eciesDecryptor);

            // Decrypt request data
            EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKeyBytes, macBytes, encryptedDataBytes);
            byte[] decryptedData = eciesDecryptor.decryptRequest(cryptogram);
            eciesEncryption.setDecryptedRequest(decryptedData);
        } catch (Exception ex) {
            throw new PowerAuthEncryptionException("Invalid HTTP request");
        }

        return eciesEncryption;
    }

}
