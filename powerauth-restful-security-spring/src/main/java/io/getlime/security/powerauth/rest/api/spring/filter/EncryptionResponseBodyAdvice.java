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
package io.getlime.security.powerauth.rest.api.spring.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.model.PowerAuthRequestObjects;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

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
     * @param converterClass Chosen HTTP message converter class.
     * @return Whether method supports encryption.
     */
    @Override
    public boolean supports(@NonNull MethodParameter methodParameter, @NonNull Class<? extends HttpMessageConverter<?>> converterClass) {
        return methodParameter.hasMethodAnnotation(PowerAuthEncryption.class) && converterClass.isAssignableFrom(MappingJackson2HttpMessageConverter.class);
    }

    /**
     * Encrypt response before writing body.
     *
     * @param response Response object.
     * @param methodParameter Method parameter.
     * @param mediaType Media type.
     * @param converter Chosen HTTP message converter class.
     * @param serverHttpRequest HTTP request.
     * @param serverHttpResponse HTTP response.
     * @return ECIES cryptogram.
     */
    @Override
    public EciesEncryptedResponse beforeBodyWrite(Object response, @NonNull MethodParameter methodParameter, @NonNull MediaType mediaType, @NonNull Class<? extends HttpMessageConverter<?>> converter, @NonNull ServerHttpRequest serverHttpRequest, @NonNull ServerHttpResponse serverHttpResponse) {
        if (response == null) {
            return null;
        }

        // Extract ECIES encryption object from HTTP request
        final HttpServletRequest httpServletRequest = ((ServletServerHttpRequest) serverHttpRequest).getServletRequest();
        final PowerAuthEciesEncryption eciesEncryption = (PowerAuthEciesEncryption) httpServletRequest.getAttribute(PowerAuthRequestObjects.ENCRYPTION_OBJECT);
        if (eciesEncryption == null) {
            return null;
        }

        // Convert response to JSON
        try {
            byte[] responseBytes = serializeResponseObject(response);

            // Encrypt response using decryptor and return ECIES cryptogram
            final EciesDecryptor eciesDecryptor = eciesEncryption.getEciesDecryptor();
            EciesCryptogram cryptogram = eciesDecryptor.encryptResponse(responseBytes);
            String encryptedDataBase64 = BaseEncoding.base64().encode(cryptogram.getEncryptedData());
            String macBase64 = BaseEncoding.base64().encode(cryptogram.getMac());

            // Return encrypted response
            return new EciesEncryptedResponse(encryptedDataBase64, macBase64);
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * Serialize response object to byte[].
     *
     * @param response Response object.
     * @return Response data as byte[].
     * @throws IOException In case JSON serialization fails.
     */
    private byte[] serializeResponseObject(Object response) throws IOException {
        if (response.getClass() == byte[].class) {
            // Response data is raw byte[], data conversion is not required
            return (byte[]) response;
        } else {
            // Convert response object to byte[] using ObjectMapper
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            objectMapper.writeValue(baos, response);
            return baos.toByteArray();
        }
    }

}
