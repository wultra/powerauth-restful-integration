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
package io.getlime.security.powerauth.app.rest.api.spring.controller.v3;

import io.getlime.security.powerauth.app.rest.api.spring.provider.DefaultCustomActivationProvider;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.rest.api.base.encryption.EciesEncryptionContext;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.spring.annotation.EncryptedRequestBody;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import io.getlime.security.powerauth.rest.api.spring.service.v3.ActivationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Sample controller for a custom activation implementation.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("CustomActivationControllerV3")
@RequestMapping(value = "/pa/activation/direct")
public class CustomActivationController {

    private ActivationService activationService;

    @Autowired
    public void setActivationService(ActivationService activationService) {
        this.activationService = activationService;
    }

    /**
     * Sample custom activation implementation for version 3 of activations. In version 3 the default implementation
     * can be reused by implementing a custom activation provider which handles the logic during the activation.
     *
     * See {@link DefaultCustomActivationProvider} and
     * {@link ActivationService}.
     *
     * @param request Activation request encrypted using ECIES.
     * @param eciesContext ECIES encryption context.
     * @return ECIES encrypted activation response.
     * @throws PowerAuthActivationException In case custom activation fails.
     */
    @RequestMapping(value = "v3/create", method = RequestMethod.POST)
    @PowerAuthEncryption(scope = EciesScope.ACTIVATION_SCOPE)
    public ActivationLayer1Response createActivationV3(@EncryptedRequestBody ActivationLayer1Request request,
                                                                     EciesEncryptionContext eciesContext) throws PowerAuthActivationException {
        if (request == null || eciesContext == null) {
            throw new PowerAuthActivationException();
        }
        return activationService.createActivation(request, eciesContext);
    }

}
