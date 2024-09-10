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
package io.getlime.security.powerauth.rest.api.spring.service.oidc;

import lombok.Getter;
import lombok.Setter;

/**
 * OIDC activation configuration.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Getter
@Setter
public class OidcApplicationConfiguration {

    private String providerId;

    private String clientId;

    private String clientSecret;

    /**
     * Optional. If emtpy, {@code client_secret_basic} is used.
     */
    private ClientAuthenticationMethod clientAuthenticationMethod;

    private String issuerUri;

    private String tokenUri;

    private String jwkSetUri;

    private String redirectUri;

    private String scopes;

    private String authorizeUri;

    /**
     * Optional. If empty, {code RS256} is used.
     */
    private String signatureAlgorithm;

    /**
     * A hint for the mobile application whether to user PKCE.
     * If set to {@code true}, {@code codeVerifier} must be present in identity attributes during create activation step.
     */
    private boolean pkceEnabled;

}
