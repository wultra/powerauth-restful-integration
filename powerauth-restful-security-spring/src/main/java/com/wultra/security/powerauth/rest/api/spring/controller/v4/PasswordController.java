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

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuth;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthPasswordException;
import com.wultra.security.powerauth.rest.api.spring.service.v4.PasswordService;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthAuthenticationUtil;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for password change.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@RestController("passwordControllerV4")
@RequestMapping("/pa/v4/password")
@AllArgsConstructor
public class PasswordController {

    private final PasswordService passwordService;

    /**
     * Change the password.
     * @param request Encrypted request.
     * @param auth Automatically injected PowerAuth authentication object.
     * @return Encrypted response.
     * @throws PowerAuthAuthenticationException In case any error occurs, including authentication code validation errors.
     */
    @PostMapping(value = "change")
    @PowerAuth(resourceId = "/pa/password/change", authenticationCodeType = PowerAuthCodeType.POSSESSION_KNOWLEDGE)
    public AeadEncryptedResponse changePassword(@RequestBody AeadEncryptedRequest request, PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException, PowerAuthPasswordException {
        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersion(auth.getVersion());
        PowerAuthVersionUtil.checkEncryptionParameters(auth.getVersion(), request);
        return passwordService.changePassword(request, auth);
    }

}
