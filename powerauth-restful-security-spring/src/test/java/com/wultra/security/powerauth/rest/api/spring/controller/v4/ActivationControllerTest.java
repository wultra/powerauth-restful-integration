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
import com.wultra.security.powerauth.rest.api.model.entity.ActivationType;
import com.wultra.security.powerauth.rest.api.model.request.ActivationRenameRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.rest.api.model.request.v4.ActivationLayer1Request;
import com.wultra.security.powerauth.rest.api.model.request.v4.ActivationStatusRequest;
import com.wultra.security.powerauth.rest.api.model.response.ActivationDetailResponse;
import com.wultra.security.powerauth.rest.api.model.response.v4.ActivationLayer1Response;
import com.wultra.security.powerauth.rest.api.model.response.v4.ActivationStatusResponse;
import com.wultra.security.powerauth.rest.api.spring.annotation.support.PowerAuthEncryptionArgumentResolver;
import com.wultra.security.powerauth.rest.api.spring.annotation.support.PowerAuthWebArgumentResolver;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthActivation;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.config.ServiceConfiguration;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionScope;
import com.wultra.security.powerauth.rest.api.spring.encryption.PowerAuthEncryptorData;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthExceptionHandler;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthCodeInvalidException;
import com.wultra.security.powerauth.rest.api.spring.model.PowerAuthRequestObjects;
import com.wultra.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import com.wultra.security.powerauth.rest.api.spring.service.v4.ActivationService;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.validation.beanvalidation.MethodValidationPostProcessor;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        final LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.setMessageInterpolator(new ParameterMessageInterpolator());
        validator.afterPropertiesSet();
        // Reproduce the production @Validated controller behaviour, where method-level
        // validation is applied by an AOP proxy created by MethodValidationPostProcessor.
        final MethodValidationPostProcessor postProcessor = new MethodValidationPostProcessor();
        postProcessor.setValidator(validator);
        postProcessor.afterPropertiesSet();
        final ActivationController proxied = (ActivationController) postProcessor.postProcessAfterInitialization(tested, "activationControllerV4");
        mockMvc = MockMvcBuilders.standaloneSetup(proxied)
                .setCustomArgumentResolvers(new PowerAuthEncryptionArgumentResolver(), new PowerAuthWebArgumentResolver())
                .setControllerAdvice(new PowerAuthExceptionHandler())
                .setValidator(validator)
                .build();
    }

    @Test
    void renameActivation_rejectsBlankActivationName() throws Exception {
        mockMvc.perform(post("/pa/v4/activation/rename")
                        .contentType(MediaType.APPLICATION_JSON)
                        .requestAttr(PowerAuthRequestObjects.ENCRYPTION_OBJECT, encryptorData("{\"activationName\":\"\"}")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseObject.code").value("ERR_VALIDATION"));
        verifyNoInteractions(activationService);
    }

    @Test
    void renameActivation_rejectsMissingActivationName() throws Exception {
        mockMvc.perform(post("/pa/v4/activation/rename")
                        .contentType(MediaType.APPLICATION_JSON)
                        .requestAttr(PowerAuthRequestObjects.ENCRYPTION_OBJECT, encryptorData("{}")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseObject.code").value("ERR_VALIDATION"));
        verifyNoInteractions(activationService);
    }

    @Test
    void renameActivation_rejectsWhitespaceOnlyActivationName() throws Exception {
        mockMvc.perform(post("/pa/v4/activation/rename")
                        .contentType(MediaType.APPLICATION_JSON)
                        .requestAttr(PowerAuthRequestObjects.ENCRYPTION_OBJECT, encryptorData("{\"activationName\":\"   \"}")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseObject.code").value("ERR_VALIDATION"));
        verifyNoInteractions(activationService);
    }

    @Test
    void renameActivation_rejectsNullRequest() throws Exception {
        mockMvc.perform(post("/pa/v4/activation/rename")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.responseObject.code").value("ERR_AUTHENTICATION"));
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

    @Test
    void createActivation_rejectsNullType() throws Exception {
        mockMvc.perform(post("/pa/v4/activation/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .requestAttr(PowerAuthRequestObjects.ENCRYPTION_OBJECT, encryptorData("{\"identityAttributes\":{},\"activationData\":{}}", EncryptionScope.APPLICATION_SCOPE)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseObject.code").value("ERR_VALIDATION"));
        verifyNoInteractions(activationService);
    }

    @Test
    void createActivation_rejectsNullIdentityAttributes() throws Exception {
        mockMvc.perform(post("/pa/v4/activation/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .requestAttr(PowerAuthRequestObjects.ENCRYPTION_OBJECT, encryptorData("{\"type\":\"CODE\",\"activationData\":{}}", EncryptionScope.APPLICATION_SCOPE)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseObject.code").value("ERR_VALIDATION"));
        verifyNoInteractions(activationService);
    }

    @Test
    void createActivation_rejectsNullActivationData() throws Exception {
        mockMvc.perform(post("/pa/v4/activation/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .requestAttr(PowerAuthRequestObjects.ENCRYPTION_OBJECT, encryptorData("{\"type\":\"CODE\",\"identityAttributes\":{}}", EncryptionScope.APPLICATION_SCOPE)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseObject.code").value("ERR_VALIDATION"));
        verifyNoInteractions(activationService);
    }

    @Test
    void createActivation_rejectsAllNullFields() throws Exception {
        mockMvc.perform(post("/pa/v4/activation/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .requestAttr(PowerAuthRequestObjects.ENCRYPTION_OBJECT, encryptorData("{}", EncryptionScope.APPLICATION_SCOPE)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseObject.code").value("ERR_VALIDATION"));
        verifyNoInteractions(activationService);
    }

    @Test
    void createActivation_rejectsNullRequest() throws Exception {
        mockMvc.perform(post("/pa/v4/activation/create")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseObject.code").value("ERR_ACTIVATION"));
        verifyNoInteractions(activationService);
    }

    @Test
    void createActivation_validRequestInvokesService() throws Exception {
        final ActivationLayer1Request request = new ActivationLayer1Request();
        request.setType(ActivationType.CODE);
        request.setIdentityAttributes(Map.of("code", "12345"));
        request.setActivationData(new AeadEncryptedRequest());
        final EncryptionContext context = new EncryptionContext("appKey", null, "4.0", null, EncryptionScope.APPLICATION_SCOPE);
        final ActivationLayer1Response expected = new ActivationLayer1Response();
        when(activationService.createActivation(request, context)).thenReturn(expected);

        final ActivationLayer1Response response = tested.createActivation(request, context);

        assertEquals(expected, response);
        verify(activationService).createActivation(request, context);
    }

    @Test
    void getActivationStatus_rejectsNullRequest() throws Exception {
        mockMvc.perform(post("/pa/v4/activation/status")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseObject.code").value("ERR_ACTIVATION"));
        verifyNoInteractions(activationService);
    }

    @Test
    void getActivationStatus_validRequestInvokesService() throws Exception {
        final ActivationStatusRequest request = new ActivationStatusRequest();
        final EncryptionContext context = new EncryptionContext("appKey", ACTIVATION_ID, "4.0", null, EncryptionScope.ACTIVATION_SCOPE);
        final ActivationStatusResponse expected = new ActivationStatusResponse();
        when(activationService.getActivationStatus(ACTIVATION_ID)).thenReturn(expected);

        final ActivationStatusResponse response = tested.getActivationStatus(request, context);

        assertEquals(expected, response);
        verify(activationService).getActivationStatus(ACTIVATION_ID);
    }

    private static PowerAuthEncryptorData encryptorData(final String decryptedJson) {
        return encryptorData(decryptedJson, EncryptionScope.ACTIVATION_SCOPE);
    }

    private static PowerAuthEncryptorData encryptorData(final String decryptedJson, final EncryptionScope scope) {
        final String activationId = scope == EncryptionScope.APPLICATION_SCOPE ? null : ACTIVATION_ID;
        final EncryptionContext context = new EncryptionContext("appKey", activationId, "4.0", null, scope);
        final PowerAuthEncryptorData data = new PowerAuthEncryptorData(context);
        data.setDecryptedRequest(decryptedJson.getBytes(StandardCharsets.UTF_8));
        return data;
    }

}
