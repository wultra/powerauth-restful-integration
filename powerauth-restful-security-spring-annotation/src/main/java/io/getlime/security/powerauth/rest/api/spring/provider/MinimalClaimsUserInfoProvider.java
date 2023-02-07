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
package io.getlime.security.powerauth.rest.api.spring.provider;

import com.wultra.core.annotations.PublicSpi;
import io.getlime.security.powerauth.rest.api.spring.model.UserInfoContext;

import javax.annotation.Nonnull;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Specialization of {@link UserInfoProvider}.
 * Claims {@code sub, jti, iat} are filled.
 * UserInfo is always returned, even for activation.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@PublicSpi
public class MinimalClaimsUserInfoProvider implements UserInfoProvider{

    /**
     * Always true, even for activation.
     * <p>
     * {@inheritDoc}
     */
    @Override
    public boolean shouldReturnUserInfo(@Nonnull UserInfoContext context) {
        return true;
    }

    /**
     * Fill claims {@code sub, jti, iat}.
     * <p>
     * {@inheritDoc}
     */
    @Override
    public Map<String, Object> fetchUserClaimsForUserId(@Nonnull UserInfoContext context) {
        return minimalClaims(context);
    }

    /**
     * Prepare a set of minimal claims <code>sub</code>, <code>jti</code> and <code>iat</code>.
     *
     * @param context User info context object.
     * @return Map of claims obtained for a given user ID.
     */
    private static Map<String, Object> minimalClaims(@Nonnull UserInfoContext context) {
        final Map<String, Object> defaultClaims = new LinkedHashMap<>();
        defaultClaims.put("sub", context.getUserId());
        defaultClaims.put("jti", UUID.randomUUID().toString());
        defaultClaims.put("iat", Instant.now().getEpochSecond());
        return Collections.unmodifiableMap(defaultClaims);
    }
}
