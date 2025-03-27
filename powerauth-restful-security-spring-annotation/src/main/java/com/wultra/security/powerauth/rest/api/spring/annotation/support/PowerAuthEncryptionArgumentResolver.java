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
package com.wultra.security.powerauth.rest.api.spring.annotation.support;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.wultra.security.powerauth.rest.api.spring.annotation.EncryptedRequestBody;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import com.wultra.security.powerauth.rest.api.spring.encryption.PowerAuthEncryptorData;
import com.wultra.security.powerauth.rest.api.spring.model.PowerAuthRequestObjects;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.lang.NonNull;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.io.IOException;
import java.lang.reflect.Type;

/**
 * Argument resolver for {@link PowerAuthEncryptorData} objects. It enables automatic
 * parameter resolution for methods that are annotated via {@link PowerAuthEncryptorData} annotation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthEncryptionArgumentResolver implements HandlerMethodArgumentResolver {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthEncryptionArgumentResolver.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean supportsParameter(@NonNull MethodParameter parameter) {
        return parameter.hasMethodAnnotation(PowerAuthEncryption.class)
                && (parameter.hasParameterAnnotation(EncryptedRequestBody.class) || EncryptionContext.class.isAssignableFrom(parameter.getParameterType()));
    }

    @Override
    public Object resolveArgument(@NonNull MethodParameter parameter, ModelAndViewContainer mavContainer, @NonNull NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        final HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
        final PowerAuthEncryptorData encryptorData = (PowerAuthEncryptorData) request.getAttribute(PowerAuthRequestObjects.ENCRYPTION_OBJECT);
        // Decrypted object is inserted into parameter annotated by @EncryptedRequestBody annotation
        if (parameter.hasParameterAnnotation(EncryptedRequestBody.class) && encryptorData != null && encryptorData.getDecryptedRequest() != null) {
            final Type requestType = parameter.getGenericParameterType();
            if (requestType.equals(byte[].class)) {
                return encryptorData.getDecryptedRequest();
            } else {
                try {
                    // Object is deserialized from JSON based on request type
                    final TypeFactory typeFactory = objectMapper.getTypeFactory();
                    final JavaType requestJavaType = typeFactory.constructType(requestType);
                    return objectMapper.readValue(encryptorData.getDecryptedRequest(), requestJavaType);
                } catch (IOException ex) {
                    logger.warn("Invalid request, error: {}", ex.getMessage());
                    logger.debug("Error details", ex);
                    return null;
                }
            }
        }
        // Encryption object is inserted into parameter which is of type PowerAuthEncryption
        if (encryptorData != null && EncryptionContext.class.isAssignableFrom(parameter.getParameterType())) {
            // Set encryption scope in case it is specified by the @PowerAuthEncryption annotation
            final PowerAuthEncryption powerAuthEncryption = parameter.getMethodAnnotation(PowerAuthEncryption.class);
            if (powerAuthEncryption != null) {
                EncryptionContext encryptionContext = encryptorData.getContext();
                boolean validScope = validateEncryptionScope(encryptionContext);
                if (validScope) {
                    return encryptionContext;
                }
            }
        }
        return null;
    }

    /**
     * Validate that encryption HTTP header contains correct values for given encryption scope.
     * @param encryptionContext Encryption context.
     */
    private boolean validateEncryptionScope(EncryptionContext encryptionContext) {
        switch (encryptionContext.getEncryptionScope()) {
            case ACTIVATION_SCOPE -> {
                if (!StringUtils.hasLength(encryptionContext.getApplicationKey())) {
                    logger.warn("Encryption activation scope is invalid because of missing application key");
                    return false;
                }
                if (!StringUtils.hasLength(encryptionContext.getActivationId())) {
                    logger.warn("Encryption activation scope is invalid because of missing activation ID");
                    return false;
                }
            }
            case APPLICATION_SCOPE -> {
                if (!StringUtils.hasLength(encryptionContext.getApplicationKey())) {
                    logger.warn("Encryption application scope is invalid because of missing application key");
                    return false;
                }
            }
            default -> {
                logger.warn("Unsupported encryption scope: {}", encryptionContext.getEncryptionScope());
                return false;
            }
        }
        return true;
    }

}
