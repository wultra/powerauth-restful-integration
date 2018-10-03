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

package io.getlime.security.powerauth.rest.api.spring.annotation;

import com.fasterxml.jackson.databind.JsonNode;
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
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthEncryptionProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

@Component
public class PowerAuthAnnotationInterceptor extends HandlerInterceptorAdapter {

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
                Logger.getLogger(this.getClass().getName()).log(Level.SEVERE, "You cannot use both @PowerAuth and @PowerAuthToken on same handler method. We are removing both.");
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
                    // silently ignore here and make sure authentication object is null
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
                    // silently ignore here and make sure authentication object is null
                    request.setAttribute(PowerAuth.AUTHENTICATION_OBJECT, null);
                }
            }

            // Resolve @PowerAuthEncryption annotation
            if (powerAuthEncryptionAnnotation != null) {
                try {
                    PowerAuthEciesEncryption eciesEncryption = decryptRequest(request);
                    request.setAttribute(PowerAuthEncryption.ENCRYPTION_OBJECT, eciesEncryption);
                } catch (PowerAuthEncryptionException ex) {
                    // silently ignore here and make sure authentication object is null
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
        // Read ECIES metadata from HTTP header
        final PowerAuthEciesEncryption eciesEncryption = this.encryptionProvider.prepareEciesEncryption(request.getHeader(PowerAuthEncryptionHttpHeader.HEADER_NAME));

        try {
            // Extract request body from HTTP request
            Scanner scanner = new Scanner(request.getInputStream()).useDelimiter("\\A");
            String requestBody = scanner.hasNext() ? scanner.next() : null;
            if (requestBody == null) {
                throw new PowerAuthEncryptionException("Invalid HTTP request");
            }

            // Parse ECIES cryptogram from request body
            final EciesCryptogram eciesCryptogram = parseEciesCryptogram(requestBody);

            // Prepare ephemeral public key
            final String ephemeralPublicKey = BaseEncoding.base64().encode(eciesCryptogram.getEphemeralPublicKey());

            // Obtain ECIES decryptor parameters from PowerAuth server
            final PowerAuthEciesDecryptorParameters decryptorParameters = this.encryptionProvider.getEciesDecryptorParameters(eciesEncryption.getActivationId(),
                    eciesEncryption.getApplicationKey(), ephemeralPublicKey);

            // Prepare envelope key and sharedInfo2 parameter for decryptor
            final byte[] secretKey = BaseEncoding.base64().decode(decryptorParameters.getSecretKey());
            final EciesEnvelopeKey envelopeKey = new EciesEnvelopeKey(secretKey, eciesCryptogram.getEphemeralPublicKey());
            final byte[] sharedInfo2 = BaseEncoding.base64().decode(decryptorParameters.getSharedInfo2());

            // Construct decryptor and set it to the request for later encryption of response
            final EciesDecryptor eciesDecryptor = eciesFactory.getEciesDecryptor(envelopeKey, sharedInfo2);
            eciesEncryption.setEciesDecryptor(eciesDecryptor);

            // Decrypt request data
            byte[] decryptedData = eciesDecryptor.decryptRequest(eciesCryptogram);
            eciesEncryption.setDecryptedRequest(decryptedData);
        } catch (Exception ex) {
            throw new PowerAuthEncryptionException("Invalid HTTP request");
        }

        return eciesEncryption;
    }

    /**
     * Read ECIES cryptogram from HTTP request.
     *
     * @param requestBody Request data in JSON format.
     * @return ECIES Cryptogram.
     * @throws PowerAuthEncryptionException In case JSON parsing fails.
     */
    private EciesCryptogram parseEciesCryptogram(String requestBody) throws PowerAuthEncryptionException {
        try {
            // Parse JSON data into JsonNode
            final JsonNode requestNode = objectMapper.readTree(requestBody);

            // Find ECIES cryptogram in data
            final List<String> ephemeralPublicKeyList = requestNode.findValuesAsText("ephemeralPublicKey");
            final List<String> encryptedDataList = requestNode.findValuesAsText("encryptedData");
            final List<String> macList = requestNode.findValuesAsText("mac");

            // Make sure ECIES cryptogram parameters are each present exactly once
            if (ephemeralPublicKeyList.size() != 1 || encryptedDataList.size() != 1 || macList.size() != 1) {
                throw new PowerAuthEncryptionException("Invalid HTTP request");
            }

            // Construct ECIES cryptogram from parsed data
            final byte[] ephemeralPublicKeyBytes = BaseEncoding.base64().decode(ephemeralPublicKeyList.get(0));
            final byte[] encryptedDataBytes = BaseEncoding.base64().decode(encryptedDataList.get(0));
            final byte[] macBytes = BaseEncoding.base64().decode(macList.get(0));
            return new EciesCryptogram(ephemeralPublicKeyBytes, macBytes, encryptedDataBytes);
        } catch (Exception ex) {
            throw new PowerAuthEncryptionException("Invalid HTTP request");
        }
    }
}
