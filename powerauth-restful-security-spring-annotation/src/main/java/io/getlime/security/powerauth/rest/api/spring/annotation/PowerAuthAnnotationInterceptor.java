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

import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.base.model.PowerAuthRequestObjects;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthEncryptionProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;

@Component
public class PowerAuthAnnotationInterceptor extends HandlerInterceptorAdapter {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthAnnotationInterceptor.class);

    private PowerAuthAuthenticationProvider authenticationProvider;
    private PowerAuthEncryptionProvider encryptionProvider;

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
                logger.warn("You cannot use both @PowerAuth and @PowerAuthToken on same handler method. We are removing both.");
                powerAuthSignatureAnnotation = null;
                powerAuthTokenAnnotation = null;
            }

            // Resolve @PowerAuthEncryption annotation. The order of processing is important, PowerAuth expects
            // sign-then-encrypt sequence in case both authorization and encryption are used.
            if (powerAuthEncryptionAnnotation != null) {
                Class<?> requestType = resolveGenericParameterTypeForEcies(handlerMethod);
                try {
                    encryptionProvider.decryptRequest(request, requestType, powerAuthEncryptionAnnotation.scope());
                    // Encryption object is saved in HTTP servlet request by encryption provider, so that it is available for both Spring and Java EE
                } catch (PowerAuthEncryptionException ex) {
                    logger.warn("Decryption failed, error: {}", ex.getMessage());
                }
            }

            // Resolve @PowerAuth annotation
            if (powerAuthSignatureAnnotation != null) {

                try {
                    PowerAuthApiAuthentication authentication = authenticationProvider.validateRequestSignature(
                            request,
                            powerAuthSignatureAnnotation.resourceId(),
                            request.getHeader(PowerAuthSignatureHttpHeader.HEADER_NAME),
                            new ArrayList<>(Arrays.asList(powerAuthSignatureAnnotation.signatureType()))
                    );
                    request.setAttribute(PowerAuthRequestObjects.AUTHENTICATION_OBJECT, authentication);
                } catch (PowerAuthAuthenticationException ex) {
                    logger.warn("Invalid request signature, authentication object was removed");
                    request.setAttribute(PowerAuthRequestObjects.AUTHENTICATION_OBJECT, null);
                }

            }

            // Resolve @PowerAuthToken annotation
            if (powerAuthTokenAnnotation != null) {
                try {
                    PowerAuthApiAuthentication authentication = authenticationProvider.validateToken(
                            request.getHeader(PowerAuthTokenHttpHeader.HEADER_NAME),
                            new ArrayList<>(Arrays.asList(powerAuthTokenAnnotation.signatureType()))
                    );
                    request.setAttribute(PowerAuthRequestObjects.AUTHENTICATION_OBJECT, authentication);
                } catch (PowerAuthAuthenticationException ex) {
                    logger.warn("Invalid token, authentication object was removed");
                    request.setAttribute(PowerAuthRequestObjects.AUTHENTICATION_OBJECT, null);
                }
            }

        }

        return super.preHandle(request, response, handler);
    }

    /**
     * Resolve type of request object which is annotated by the @EncryptedRequestBody annotation.
     * In case such parameter is missing the Object.class type is returned.
     *
     * @param handlerMethod Handler method.
     * @return Resolved type of request object.
     */
    private Class<?> resolveGenericParameterTypeForEcies(HandlerMethod handlerMethod) {
        for (MethodParameter parameter: handlerMethod.getMethodParameters()) {
            if (parameter.hasParameterAnnotation(EncryptedRequestBody.class)) {
                return parameter.getParameterType();
            }
        }
        return Object.class;
    }

}
