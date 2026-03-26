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
package com.wultra.security.powerauth.rest.api.model.request;

import com.wultra.security.powerauth.rest.api.model.request.v4.*;
import jakarta.validation.*;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for model validations.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class ModelValidationTest {

    private Validator validator;

    @BeforeEach
    void setUp() {
        validator = Validation.byDefaultProvider()
                .configure()
                .messageInterpolator(new ParameterMessageInterpolator())
                .buildValidatorFactory()
                .getValidator();
    }

    @Test
    void activationLayer1Request_shouldFailOnNulls() {
        ActivationLayer1Request request = new ActivationLayer1Request();

        var violations = validator.validate(request);

        assertThat(violations).extracting(v -> v.getPropertyPath().toString())
                .contains("type", "identityAttributes", "activationData");
    }

    @Test
    void devicePublicKeys_shouldFailOnBlankEcdsa() {
        DevicePublicKeys keys = new DevicePublicKeys();
        keys.setEcdsa("");

        var violations = validator.validate(keys);

        assertThat(violations).extracting(v -> v.getPropertyPath().toString())
                .contains("ecdsa");
    }

    @Test
    void sharedSecretRequest_shouldFailOnInvalidFields() {
        SharedSecretRequest request = new SharedSecretRequest();
        request.setAlgorithm("");
        request.setEncapsulationKeys(Collections.emptyList());

        var violations = validator.validate(request);

        assertThat(violations).extracting(v -> v.getPropertyPath().toString())
                .contains("algorithm", "encapsulationKeys");
    }

    @Test
    void upgradeRequestPayload_shouldFailOnNullNested() {
        UpgradeRequestPayload payload = new UpgradeRequestPayload();

        var violations = validator.validate(payload);

        assertThat(violations).extracting(v -> v.getPropertyPath().toString())
                .contains("sharedSecretRequest", "devicePublicKeys");
    }

    @Test
    void activationRenameRequest_shouldFailOnBlankName() {
        ActivationRenameRequest request = new ActivationRenameRequest();
        request.setActivationName("");

        var violations = validator.validate(request);

        assertThat(violations).isNotEmpty();
    }

    @Test
    void temporaryKeyRequest_shouldFailOnBlankJwt() {
        TemporaryKeyRequest request = new TemporaryKeyRequest();
        request.setJwt("");

        var violations = validator.validate(request);

        assertThat(violations).isNotEmpty();
    }

    @Test
    void tokenRemoveRequest_shouldFailOnBlankTokenId() {
        TokenRemoveRequest request = new TokenRemoveRequest();
        request.setTokenId("");

        var violations = validator.validate(request);

        assertThat(violations).isNotEmpty();
    }

}