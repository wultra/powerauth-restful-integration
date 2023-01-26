/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2023 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.spring.controller.v3;

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.rest.api.model.request.v3.UserInfoRequest;
import io.getlime.security.powerauth.rest.api.spring.annotation.EncryptedRequestBody;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthToken;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthUserInfoException;
import io.getlime.security.powerauth.rest.api.spring.service.v3.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Controller that provides a user information.
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController
@RequestMapping("/pa/v3/user")
public class UserInfoController {

    private final UserInfoService userInfoService;

    /**
     * Default constructor.
     * @param userInfoService User info service.
     */
    @Autowired
    public UserInfoController(UserInfoService userInfoService) {
        this.userInfoService = userInfoService;
    }

    /**
     * Fetch user info.
     *
     * @param request Request with user info service.
     * @param authentication PowerAuth Authentication.
     * @return Encrypted user info claims.
     * @throws PowerAuthUserInfoException In case there is an error while fetching claims.
     */
    @PowerAuthEncryption(scope = EciesScope.ACTIVATION_SCOPE)
    @PowerAuthToken(signatureType = {
            PowerAuthSignatureTypes.POSSESSION,
            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE
    })
    @PostMapping("info")
    public Map<String, Object> claims(@EncryptedRequestBody UserInfoRequest request, PowerAuthApiAuthentication authentication) throws PowerAuthUserInfoException {
        return userInfoService.fetchUserClaimsByUserId(
                authentication.getUserId(),
                authentication.getActivationContext().getActivationId(),
                authentication.getApplicationId()
        );
    }

}
