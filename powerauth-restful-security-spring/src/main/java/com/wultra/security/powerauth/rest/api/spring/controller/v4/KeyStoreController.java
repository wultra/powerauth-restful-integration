/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.api.spring.controller.v4;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.rest.api.model.request.TemporaryKeyRequest;
import com.wultra.security.powerauth.rest.api.model.response.TemporaryKeyResponse;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthTemporaryKeyException;
import com.wultra.security.powerauth.rest.api.spring.service.v4.KeyStoreService;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for obtaining temporary encryption keys.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("keyStoreControllerV4")
@AllArgsConstructor
@RequestMapping(value = "/pa/v4/keystore")
public class KeyStoreController {

    private static final Logger logger = LoggerFactory.getLogger(KeyStoreController.class);

    private final KeyStoreService service;

    /**
     * Create a new temporary key.
     * @param request Request for temporary key.
     * @return Response with temporary key.
     * @throws PowerAuthTemporaryKeyException In case temporary key cannot be returned.
     */
    @PostMapping("create")
    public ObjectResponse<TemporaryKeyResponse> fetchTemporaryKey(@RequestBody ObjectRequest<TemporaryKeyRequest> request) throws PowerAuthTemporaryKeyException {
        logger.info("action: fetchTemporaryKey, state: initiated");
        if (request == null) {
            logger.warn("Null request while fetching temporary key");
            throw new PowerAuthTemporaryKeyException();
        }
        final TemporaryKeyRequest requestObject = request.getRequestObject();
        if (requestObject == null) {
            logger.warn("Null request object while fetching temporary key");
            throw new PowerAuthTemporaryKeyException();
        }
        if (!StringUtils.hasLength(requestObject.getJwt())) {
            logger.warn("Invalid request object with empty JWT while fetching temporary key");
            throw new PowerAuthTemporaryKeyException();
        }
        final ObjectResponse<TemporaryKeyResponse> response = new ObjectResponse<>(service.fetchTemporaryKey(requestObject));
        logger.info("action: fetchTemporaryKey, state: succeeded");
        return response;
    }

}
