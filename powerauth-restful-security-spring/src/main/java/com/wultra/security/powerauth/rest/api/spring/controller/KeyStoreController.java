/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2024 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.api.spring.controller;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.rest.api.model.request.TemporaryKeyRequest;
import com.wultra.security.powerauth.rest.api.model.response.TemporaryKeyResponse;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthTemporaryKeyException;
import com.wultra.security.powerauth.rest.api.spring.service.KeyStoreService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for obtaining temporary encryption keys.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.3</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("keyStoreControllerV3")
@RequestMapping(value = "/pa/v3/keystore")
public class KeyStoreController {

    private static final Logger logger = LoggerFactory.getLogger(KeyStoreController.class);

    private final KeyStoreService service;

    /**
     * Default autowiring constructor.
     * @param service Keystore service.
     */
    @Autowired
    public KeyStoreController(KeyStoreService service) {
        this.service = service;
    }

    /**
     * Create a new temporary key.
     * @param request Request for temporary key.
     * @return Response with temporary key.
     * @throws PowerAuthTemporaryKeyException In case temporary key cannot be returned.
     */
    @PostMapping("create")
    public ObjectResponse<TemporaryKeyResponse> fetchTemporaryKey(@RequestBody ObjectRequest<TemporaryKeyRequest> request) throws PowerAuthTemporaryKeyException {
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
        return new ObjectResponse<>(service.fetchTemporaryKey(requestObject));
    }

}
