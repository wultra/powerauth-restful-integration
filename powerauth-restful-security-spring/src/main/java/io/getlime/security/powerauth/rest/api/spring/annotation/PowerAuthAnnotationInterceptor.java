/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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

package io.getlime.security.powerauth.rest.api.spring.annotation;

import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;

@Component
public class PowerAuthAnnotationInterceptor extends HandlerInterceptorAdapter {

    private PowerAuthAuthenticationProvider authenticationProvider;

    @Autowired
    public void setAuthenticationProvider(PowerAuthAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        // Check if the provided handler is related to handler method.
        // This is to avoid issues with possible CORS requests )in case of
        // incorrect filter mapping) where there are special "pre-flight"
        // requests before the actual requests.
        if (handler instanceof HandlerMethod) {

            HandlerMethod handlerMethod = (HandlerMethod) handler;
            PowerAuth powerAuthAnnotation = handlerMethod.getMethodAnnotation(PowerAuth.class);

            if (powerAuthAnnotation != null) {

                try {
                    PowerAuthApiAuthentication authentication = this.authenticationProvider.validateRequestSignature(
                            request,
                            powerAuthAnnotation.resourceId(),
                            request.getHeader(PowerAuthHttpHeader.HEADER_NAME),
                            new ArrayList<>(Arrays.asList(powerAuthAnnotation.signatureType()))
                    );
                    if (authentication != null) {
                        request.setAttribute(PowerAuth.AUTHENTICATION_OBJECT, authentication);
                    }
                } catch (PowerAuthAuthenticationException ex) {
                    // silently ignore here and make sure authentication object is null
                    request.setAttribute(PowerAuth.AUTHENTICATION_OBJECT, null);
                }

            }

        }

        return super.preHandle(request, response, handler);
    }

}
