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
package com.wultra.security.powerauth.rest.api.spring.controller.v4;

import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuth;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthBiometryException;
import com.wultra.security.powerauth.rest.api.spring.service.v4.BiometryService;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthAuthenticationUtil;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for biometry setup.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@RestController("biometryControllerV4")
@RequestMapping("/pa/v4/biometry")
@AllArgsConstructor
@Slf4j
public class BiometryController {

    private final BiometryService biometryService;

    /**
     * Set up biometry.
     * @param request Encrypted request.
     * @param auth Automatically injected PowerAuth authentication object.
     * @return Encrypted response.
     * @throws PowerAuthAuthenticationException In case any error occurs, including authentication code validation errors.
     * @throws PowerAuthBiometryException In case of biometry setup failure.
     */
    @PostMapping(value = "add")
    @PowerAuth(resourceId = "/pa/biometry/add", authenticationCodeType = PowerAuthCodeType.POSSESSION_KNOWLEDGE)
    public AeadEncryptedResponse addBiometry(@RequestBody AeadEncryptedRequest request, PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException, PowerAuthBiometryException {
        logger.info("action: addBiometry, state: initiated, activationId: {}",
                auth != null && auth.getActivationContext() != null ? auth.getActivationContext().getActivationId() : null);
        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersionV4(auth.getVersion());
        PowerAuthVersionUtil.checkEncryptionParameters(auth.getVersion(), request);
        final AeadEncryptedResponse response = biometryService.addBiometry(request, auth);
        logger.info("action: addBiometry, state: succeeded");
        return response;
    }

    /**
     * Remove biometry.
     * @param auth Automatically injected PowerAuth authentication object.
     * @return Response.
     * @throws PowerAuthAuthenticationException In case any error occurs, including authentication code validation errors.
     * @throws PowerAuthBiometryException In case of biometry removal failure.
     */
    @PostMapping(value = "remove")
    @PowerAuth(resourceId = "/pa/biometry/remove", authenticationCodeType = PowerAuthCodeType.POSSESSION)
    public Response removeBiometry(PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException, PowerAuthBiometryException {
        logger.info("action: removeBiometry, state: initiated, activationId: {}",
                auth != null && auth.getActivationContext() != null ? auth.getActivationContext().getActivationId() : null);
        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersionV4(auth.getVersion());
        final Response response = biometryService.removeBiometry(auth.getActivationContext().getActivationId());
        logger.info("action: removeBiometry, state: succeeded");
        return response;
    }

}
