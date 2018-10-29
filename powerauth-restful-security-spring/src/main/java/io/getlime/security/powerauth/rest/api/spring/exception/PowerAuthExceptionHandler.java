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
package io.getlime.security.powerauth.rest.api.spring.exception;

import io.getlime.core.rest.model.base.response.ErrorResponse;
import io.getlime.security.powerauth.rest.api.base.exception.*;
import io.getlime.security.powerauth.rest.api.spring.controller.v3.UpgradeController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Implementation of a PA2.0 Standard RESTful API exception handler.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
@ControllerAdvice
@Order(PowerAuthExceptionHandler.PRECEDENCE)
public class PowerAuthExceptionHandler {

    public static final int PRECEDENCE = -100;

    private static final Logger logger = LoggerFactory.getLogger(UpgradeController.class);

    /**
     * Handle PowerAuthAuthenticationException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthAuthenticationException.class)
    @ResponseStatus(value = HttpStatus.UNAUTHORIZED)
    public @ResponseBody ErrorResponse handleUnauthorizedException(Exception ex) {
        PowerAuthAuthenticationException paex = (PowerAuthAuthenticationException)ex;
        logger.error(paex.getMessage(), paex);
        return new ErrorResponse(paex.getDefaultCode(), paex);
    }

    /**
     * Handle PowerAuthActivationException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthActivationException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleActivationException(Exception ex) {
        PowerAuthActivationException paex = (PowerAuthActivationException)ex;
        logger.error(paex.getMessage(), paex);
        return new ErrorResponse(paex.getDefaultCode(), paex);
    }

    /**
     * Handle PowerAuthSecureVaultException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthSecureVaultException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleSecureVaultException(Exception ex) {
        PowerAuthSecureVaultException paex = (PowerAuthSecureVaultException)ex;
        logger.error(paex.getMessage(), paex);
        return new ErrorResponse(paex.getDefaultCode(), paex);
    }

    /**
     * Handle PowerAuthEncryptionException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthEncryptionException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handlePowerAuthEncryptionException(Exception ex) {
        PowerAuthEncryptionException paex = (PowerAuthEncryptionException)ex;
        logger.error(paex.getMessage(), paex);
        return new ErrorResponse(paex.getDefaultCode(), paex);
    }

    /**
     * Handle PowerAuthUpgradeException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthUpgradeException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handlePowerAuthUpgradeException(Exception ex) {
        PowerAuthUpgradeException pamx = (PowerAuthUpgradeException)ex;
        logger.error(pamx.getMessage(), pamx);
        return new ErrorResponse(pamx.getDefaultCode(), pamx);
    }

}
