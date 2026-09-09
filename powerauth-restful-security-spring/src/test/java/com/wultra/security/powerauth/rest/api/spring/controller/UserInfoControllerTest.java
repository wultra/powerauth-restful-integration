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
package com.wultra.security.powerauth.rest.api.spring.controller;

import com.wultra.security.powerauth.rest.api.spring.annotation.support.PowerAuthEncryptionArgumentResolver;
import com.wultra.security.powerauth.rest.api.spring.annotation.support.PowerAuthWebArgumentResolver;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionScope;
import com.wultra.security.powerauth.rest.api.spring.encryption.PowerAuthEncryptorData;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthExceptionHandler;
import com.wultra.security.powerauth.rest.api.spring.model.PowerAuthRequestObjects;
import com.wultra.security.powerauth.rest.api.spring.service.UserInfoService;
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

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test for {@link UserInfoController}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class UserInfoControllerTest {

    private static final String ACTIVATION_ID = "e43a5dec-afea-4f17-a92a-3b5c8a4e1b3e";

    @Mock
    private UserInfoService userInfoService;

    @InjectMocks
    private UserInfoController tested;

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
        final UserInfoController proxied = (UserInfoController) postProcessor.postProcessAfterInitialization(tested, "userInfoController");
        mockMvc = MockMvcBuilders.standaloneSetup(proxied)
                .setCustomArgumentResolvers(new PowerAuthEncryptionArgumentResolver(), new PowerAuthWebArgumentResolver())
                .setControllerAdvice(new PowerAuthExceptionHandler())
                .setValidator(validator)
                .build();
    }

    @Test
    void fetchUserInfo_rejectsNullRequest() throws Exception {
        mockMvc.perform(post("/pa/v4/user/info")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.responseObject.code").value("ERR_AUTHENTICATION"));
        verifyNoInteractions(userInfoService);
    }

    @Test
    void fetchUserInfo_validEmptyBodyInvokesService() throws Exception {
        when(userInfoService.fetchUserClaimsByActivationId(ACTIVATION_ID)).thenReturn(Map.of("sub", "user-123"));

        mockMvc.perform(post("/pa/v4/user/info")
                        .contentType(MediaType.APPLICATION_JSON)
                        .requestAttr(PowerAuthRequestObjects.ENCRYPTION_OBJECT, encryptorData("{}")))
                .andExpect(status().isOk());

        verify(userInfoService).fetchUserClaimsByActivationId(ACTIVATION_ID);
    }

    private static PowerAuthEncryptorData encryptorData(final String decryptedJson) {
        final EncryptionContext context = new EncryptionContext("appKey", ACTIVATION_ID, "4.0", null, EncryptionScope.ACTIVATION_SCOPE);
        final PowerAuthEncryptorData data = new PowerAuthEncryptorData(context);
        data.setDecryptedRequest(decryptedJson.getBytes(StandardCharsets.UTF_8));
        return data;
    }

}
