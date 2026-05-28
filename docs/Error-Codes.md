# Error Codes

The PowerAuth RESTful Integration library returns a uniform JSON error response envelope for every failure produced by the standard PowerAuth endpoints. The envelope follows the `ErrorResponse` contract:

```json
{
  "status": "ERROR",
  "responseObject": {
    "code": "ERR_AUTHENTICATION",
    "message": "POWER_AUTH_CODE_INVALID"
  }
}
```

## Authentication errors (HTTP 401)

| `code`               | `message`                           | Exception class                                                               | When it is raised                                                                                                          |
|----------------------|-------------------------------------|-------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| `ERR_AUTHENTICATION` | `POWER_AUTH_CODE_INVALID`           | `PowerAuthCodeInvalidException`, `PowerAuthAuthenticationException` (default) | PowerAuth authentication code (signature) verification failed.                                                             |
| `ERR_AUTHENTICATION` | `POWER_AUTH_CODE_ERROR`             | `PowerAuthCodeErrorException`                                                 | Generic / unexpected failure while processing an authentication code on the server side.                                   |
| `ERR_AUTHENTICATION` | `POWER_AUTH_CODE_TYPE_INVALID`      | `PowerAuthCodeTypeInvalidException`                                           | The signature type sent in the `X-PowerAuth-Authorization` header does not match the signature type the endpoint requires. |
| `ERR_AUTHENTICATION` | `POWER_AUTH_TOKEN_INVALID`          | `PowerAuthTokenInvalidException`                                              | `X-PowerAuth-Token` header validation failed — invalid token value.                                                        |
| `ERR_AUTHENTICATION` | `POWER_AUTH_TOKEN_ERROR`            | `PowerAuthTokenErrorException`                                                | Generic / unexpected failure while validating a token on the server side.                                                  |
| `ERR_AUTHENTICATION` | `POWER_AUTH_REQUEST_INVALID`        | `PowerAuthInvalidRequestException`                                            | The HTTP request itself is malformed for PowerAuth processing.                                                             |
| `ERR_AUTHENTICATION` | `POWER_AUTH_HTTP_HEADER_MISSING`    | `PowerAuthHeaderMissingException`                                             | A required PowerAuth HTTP header is missing on a protected endpoint.                                                       |
| `ERR_AUTHENTICATION` | `POWER_AUTH_REQUEST_FILTER_MISSING` | `PowerAuthRequestFilterException`                                             | `PowerAuthRequestFilter` is not registered in the servlet filter chain (configuration error).                              |

## Activation, encryption and lifecycle errors (HTTP 400)

| `code`                | `message`                            | Exception class                  | Typical cause                                                                          |
|-----------------------|--------------------------------------|----------------------------------|----------------------------------------------------------------------------------------|
| `ERR_ACTIVATION`      | `POWER_AUTH_ACTIVATION_INVALID`      | `PowerAuthActivationException`   | Failure during activation.                                                             |
| `ERR_ENCRYPTION`      | `POWER_AUTH_ENCRYPTION_FAILED`       | `PowerAuthEncryptionException`   | End-to-end encryption error.                                                           |
| `ERR_SECURE_VAULT`    | `POWER_AUTH_SECURE_VAULT_INVALID`    | `PowerAuthSecureVaultException`  | Secure vault unlock failed.                                                            |
| `ERR_UPGRADE`         | `POWER_AUTH_UPGRADE_FAILED`          | `PowerAuthUpgradeException`      | Protocol upgrade failed.                                                               |
| `ERR_TEMPORARY_KEY`   | `POWER_AUTH_TEMPORARY_KEY_FAILURE`   | `PowerAuthTemporaryKeyException` | Issuing or validating a temporary encryption key failed.                               |
| `ERR_PASSWORD_CHANGE` | `POWER_AUTH_PASSWORD_CHANGE_FAILURE` | `PowerAuthPasswordException`     | Knowledge-factor change failed.                                                        |
| `ERR_BIOMETRY`        | `POWER_AUTH_BIOMETRY_FAILURE`        | `PowerAuthBiometryException`     | Biometric factor enrollment / removal failed.                                          |
| `ERR_USER_INFO`       | `POWER_AUTH_USER_INFO_ERROR`         | `PowerAuthUserInfoException`     | The `UserInfoProvider` failed or the user-info endpoint could not assemble the claims. |
| `ERR_STATUS`          | `POWER_AUTH_STATUS_ERROR`            | `PowerAuthStatusException`       | Server status / activation status query failed.                                        |

## Validation errors (HTTP 400)

Returned for failed bean validation on request bodies and parameters.

| `code`           | When it is raised                                                                                                                            |
|------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `ERR_VALIDATION` | `MethodArgumentNotValidException` or `ConstraintViolationException`. The `message` field contains a message detailing the failed validation. |
