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
package io.getlime.security.powerauth.rest.api.spring.controller;

import io.getlime.security.powerauth.rest.api.model.request.TemporaryKeyRequest;
import io.getlime.security.powerauth.rest.api.model.response.TemporaryKeyResponse;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthTemporaryKeyException;
import io.getlime.security.powerauth.rest.api.spring.service.KeyStoreService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for obtaining temporary encryption keys.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("activationControllerV3")
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
    public @ResponseBody TemporaryKeyResponse fetchTemporaryKey(@RequestBody TemporaryKeyRequest request) throws PowerAuthTemporaryKeyException {
        if (request == null) {
            logger.warn("Invalid request while fetching temporary key");
            throw new PowerAuthTemporaryKeyException();
        }
        return service.fetchTemporaryKey(request);
    }

}
