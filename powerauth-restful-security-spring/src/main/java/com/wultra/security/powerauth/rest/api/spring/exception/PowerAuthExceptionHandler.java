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
package com.wultra.security.powerauth.rest.api.spring.exception;

import com.wultra.core.rest.model.base.response.ErrorResponse;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.stream.Collectors;

/**
 * Implementation of a PA2.0 Standard RESTful API exception handler.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
@ControllerAdvice
@Order(PowerAuthExceptionHandler.PRECEDENCE)
public class PowerAuthExceptionHandler {

    /**
     * Precedence value that makes sure to apply the filters in the right order.
     */
    public static final int PRECEDENCE = -100;

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthExceptionHandler.class);

    /**
     * Handle PowerAuthAuthenticationException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthAuthenticationException.class)
    @ResponseStatus(value = HttpStatus.UNAUTHORIZED)
    public @ResponseBody ErrorResponse handleUnauthorizedException(PowerAuthAuthenticationException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

    /**
     * Handle PowerAuthActivationException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthActivationException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleActivationException(PowerAuthActivationException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

    /**
     * Handle PowerAuthSecureVaultException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthSecureVaultException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleSecureVaultException(PowerAuthSecureVaultException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

    /**
     * Handle PowerAuthEncryptionException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthEncryptionException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handlePowerAuthEncryptionException(PowerAuthEncryptionException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

    /**
     * Handle PowerAuthUpgradeException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthUpgradeException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handlePowerAuthUpgradeException(PowerAuthUpgradeException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

    /**
     * Handle {@link PowerAuthUserInfoException} exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthUserInfoException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handlePowerAuthUserInfoException(PowerAuthUserInfoException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getMessage());
    }

    /**
     * Handle PowerAuthTemporaryKeyException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthTemporaryKeyException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handlePowerAuthTemporaryKeyException(PowerAuthTemporaryKeyException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

    /**
     * Handle PowerAuthPasswordException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthPasswordException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handlePowerAuthPasswordException(PowerAuthPasswordException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

    /**
     * Handle PowerAuthBiometryException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthBiometryException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handlePowerAuthBiometryException(PowerAuthBiometryException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

    /**
     * Handle PowerAuthUserStatusException exceptions.
     * @param ex Exception instance.
     * @return Error response.
     */
    @ExceptionHandler(value = PowerAuthStatusException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handlePowerAuthStatusException(PowerAuthStatusException ex) {
        logger.warn(ex.getMessage(), ex);
        return new ErrorResponse(ex.getDefaultCode(), ex.getDefaultError());
    }

    /**
     * Handle method argument validation errors.
     * @param ex Exception instance
     * @return Error response
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleValidationException(MethodArgumentNotValidException ex) {
        logger.warn("Request body validation failed", ex);
        String details = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(e -> e.getField() + ": " + e.getDefaultMessage())
                .collect(Collectors.joining(", "));
        return new ErrorResponse("ERR_VALIDATION", details);
    }

    /**
     * Handle constraint violation validation errors.
     * @param ex Exception instance
     * @return Error response
     */
    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public @ResponseBody ErrorResponse handleConstraintViolationException(ConstraintViolationException ex) {
        logger.warn("Constraint violation", ex);
        String details = ex.getConstraintViolations()
                .stream()
                .map(v -> v.getPropertyPath() + ": " + v.getMessage())
                .collect(Collectors.joining(", "));
        return new ErrorResponse("ERR_VALIDATION", details);
    }

}
