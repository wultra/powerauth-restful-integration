/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2018 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.rest.api.spring.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;

/**
 * Controller advice used for encryption of responses of REST endpoints.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ControllerAdvice
public class EncryptionResponseBodyAdvice implements ResponseBodyAdvice<Object> {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Whether method supports encryption.
     *
     * @param methodParameter Method parameter.
     * @param aClass HTTP message converter.
     * @return Whether method supports encryption.
     */
    @Override
    public boolean supports(MethodParameter methodParameter, Class<? extends HttpMessageConverter<?>> aClass) {
        return methodParameter.hasMethodAnnotation(PowerAuthEncryption.class);
    }

    /**
     * Encrypt response before writing body.
     *
     * @param response Response object.
     * @param methodParameter Method parameter.
     * @param mediaType Media type.
     * @param aClass HTTP message converter.
     * @param serverHttpRequest HTTP request.
     * @param serverHttpResponse HTTP response.
     * @return ECIES cryptogram.
     */
    @Override
    public EciesCryptogram beforeBodyWrite(Object response, MethodParameter methodParameter, MediaType mediaType, Class<? extends HttpMessageConverter<?>> aClass, ServerHttpRequest serverHttpRequest, ServerHttpResponse serverHttpResponse) {
        // Extract ECIES encryption object from HTTP request
        final HttpServletRequest httpServletRequest = ((ServletServerHttpRequest) serverHttpRequest).getServletRequest();
        final PowerAuthEciesEncryption eciesEncryption = (PowerAuthEciesEncryption) httpServletRequest.getAttribute(PowerAuthEncryption.ENCRYPTION_OBJECT);
        if (eciesEncryption == null) {
            return null;
        }

        // Convert response to JSON
        byte[] encryptedResponseBytes;
        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            objectMapper.writeValue(baos, response);
            encryptedResponseBytes = baos.toByteArray();

            // Encrypt response using decryptor and return ECIES cryptogram
            final EciesDecryptor eciesDecryptor = eciesEncryption.getEciesDecryptor();
            return eciesDecryptor.encryptResponse(encryptedResponseBytes);
        } catch (Exception e) {
            return null;
        }
    }
}
