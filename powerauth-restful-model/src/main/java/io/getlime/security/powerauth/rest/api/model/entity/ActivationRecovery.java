/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2019 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.model.entity;

import lombok.Data;
import lombok.ToString;

/**
 * Activation recovery model class for recovery code and PUK.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class ActivationRecovery {

    /**
     * Recovery code.
     */
    private String recoveryCode;

    /**
     * Recovery PUK.
     */
    @ToString.Exclude
    private String puk;

}