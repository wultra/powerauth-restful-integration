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
package com.wultra.security.powerauth.rest.api.spring.annotation.support;

import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuth;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthActivation;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.model.PowerAuthRequestObjects;
import org.springframework.core.MethodParameter;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Argument resolver for {@link PowerAuthApiAuthentication} objects. It enables automatic
 * parameter resolution for methods that are annotated via {@link PowerAuth} annotation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthWebArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(@NonNull MethodParameter parameter) {
        return PowerAuthApiAuthentication.class.isAssignableFrom(parameter.getParameterType())
                || PowerAuthActivation.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(@NonNull MethodParameter parameter, ModelAndViewContainer mavContainer, @NonNull NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        if (parameter.getParameterType().isAssignableFrom(PowerAuthApiAuthentication.class)) {
            HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
            PowerAuthApiAuthentication apiAuthentication = (PowerAuthApiAuthentication) request.getAttribute(PowerAuthRequestObjects.AUTHENTICATION_OBJECT);
            if (apiAuthentication == null) {
                return null;
            }
            if (apiAuthentication.getAuthenticationContext().isValid()) {
                // Return PowerAuthApiAuthentication instance only for successful authentication due to compatibility reasons
                return apiAuthentication;
            }
        }
        if (parameter.getParameterType().isAssignableFrom(PowerAuthActivation.class)) {
            HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
            PowerAuthApiAuthentication apiAuthentication = (PowerAuthApiAuthentication) request.getAttribute(PowerAuthRequestObjects.AUTHENTICATION_OBJECT);
            if (apiAuthentication == null) {
                return null;
            }
            // Activation context is returned for both successful and failed authentication
            return apiAuthentication.getActivationContext();
        }
        return null;
    }

}
