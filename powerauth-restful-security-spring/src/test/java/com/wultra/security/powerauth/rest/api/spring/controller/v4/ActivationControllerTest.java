/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2026 Wultra s.r.o.
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

import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.rest.api.model.request.ActivationRenameRequest;
import com.wultra.security.powerauth.rest.api.model.response.ActivationDetailResponse;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthActivation;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.config.ServiceConfiguration;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthCodeInvalidException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import com.wultra.security.powerauth.rest.api.spring.service.v4.ActivationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Test for {@link ActivationController}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class ActivationControllerTest {

    private static final String ACTIVATION_ID = "e43a5dec-afea-4f17-a92a-3b5c8a4e1b3e";

    @Mock
    private PowerAuthAuthenticationProvider authenticationProvider;

    @Mock
    private ActivationService activationService;

    @Mock
    private ServiceConfiguration serviceConfiguration;

    @Mock
    private PowerAuthApiAuthentication auth;

    @Mock
    private PowerAuthActivation activationContext;

    @InjectMocks
    private ActivationController tested;

    @Test
    void renameActivation_rejectsNullRequest() {
        assertThrows(PowerAuthInvalidRequestException.class, () -> tested.renameActivation(null, auth));
        verifyNoInteractions(activationService);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void renameActivation_rejectsBlankActivationName(final String activationName) {
        final ActivationRenameRequest request = new ActivationRenameRequest();
        request.setActivationName(activationName);

        assertThrows(PowerAuthInvalidRequestException.class, () -> tested.renameActivation(request, auth));
        verifyNoInteractions(activationService);
    }

    @Test
    void renameActivation_validNameInvokesService() throws Exception {
        when(auth.getActivationContext()).thenReturn(activationContext);
        when(activationContext.getActivationId()).thenReturn(ACTIVATION_ID);
        when(auth.getVersion()).thenReturn("4.0");
        final ActivationRenameRequest request = new ActivationRenameRequest();
        request.setActivationName("My Device");
        final ActivationDetailResponse detail = new ActivationDetailResponse();
        detail.setActivationId(ACTIVATION_ID);
        detail.setActivationName("My Device");
        when(activationService.renameActivation(ACTIVATION_ID, request)).thenReturn(detail);

        final ObjectResponse<ActivationDetailResponse> response = tested.renameActivation(request, auth);

        assertEquals(detail, response.getResponseObject());
        verify(activationService).renameActivation(ACTIVATION_ID, request);
    }

    @Test
    void renameActivation_validNameWithoutAuthenticationFailsAuthenticationCheck() {
        final ActivationRenameRequest request = new ActivationRenameRequest();
        request.setActivationName("My Device");

        assertThrows(PowerAuthCodeInvalidException.class, () -> tested.renameActivation(request, null));
        verifyNoInteractions(activationService);
    }

}
