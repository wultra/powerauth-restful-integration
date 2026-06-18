# PowerAuth RESTful API Methods

This document lists all REST endpoints exposed by the `powerauth-restful-security-spring` module, with full request and response object schemas. Endpoints are grouped by resource area and ordered by protocol version. v4 is the current version; v3 endpoints are kept for backward compatibility.

Responses that use the Wultra envelope are wrapped in `ObjectResponse<T>` with a top-level `status` (`"OK"`) and a `responseObject` field. An empty success response uses the `Response` type (just `status`).

For error code details see [Error Codes](Error-Codes.md).

---

## Status

### `POST /pa/v3/status`

Returns application status information.

- **Protocol versions:** 3.0, 3.1, 3.2, 3.3
- **Authentication:** none
- **Request body:** none

**Response** `ObjectResponse<ServerStatusResponse>`:

| Field                 | Type     | Description                                           |
|-----------------------|----------|-------------------------------------------------------| 
| `serverTime`          | `long`   | Current server time in milliseconds since Unix epoch. |
| `application.name`    | `String` | Application name from build properties.               |
| `application.version` | `String` | Application version from build properties.            |


---

### `POST /pa/v4/status`

Returns application status information. Extended to accept an optional application key for filtering supported algorithms.

- **Protocol versions:** 4.0
- **Authentication:** none

**Request** `ObjectRequest<ServerStatusRequest>`:

| Field            | Type     | Description                                                  |
|------------------|----------|--------------------------------------------------------------| 
| `applicationKey` | `String` | _(optional)_ Application key to filter supported algorithms. |

**Response** `ObjectResponse<ServerStatusResponse>`:

| Field                 | Type           | Description                                            |
|-----------------------|----------------|--------------------------------------------------------| 
| `serverTime`          | `long`         | Current server time in milliseconds since Unix epoch.  |
| `supportedAlgorithms` | `List<String>` | List of supported cryptographic algorithm identifiers. |
| `application.name`    | `String`       | Application name from build properties.                |
| `application.version` | `String`       | Application version from build properties.             |


| Error Code       | When                                          |
|------------------|-----------------------------------------------|
| `ERR_VALIDATION` | `applicationKey` field fails bean validation. |
---

## Key Store (Temporary Keys)

### `POST /pa/v3/keystore/create`
### `POST /pa/v4/keystore/create`

Fetches a temporary encryption key encoded as a signed JWT. v3 uses ECIES; v4 uses AEAD.

- **Protocol versions:** 3.3 (v3), 4.0 (v4)
- **Authentication:** none

**Request** `ObjectRequest<TemporaryKeyRequest>`:

| Field | Type     | Required | Description                                                    |
|-------|----------|----------|----------------------------------------------------------------|
| `jwt` | `String` | ✓        | JWT-encoded temporary key request (device public key + nonce). |

**Response** `ObjectResponse<TemporaryKeyResponse>`:

| Field | Type     | Description                                                         |
|-------|----------|---------------------------------------------------------------------|
| `jwt` | `String` | JWT-encoded temporary key response (server public key + signature). |


| Error Code          | When                              |
|---------------------|-----------------------------------|
| `ERR_TEMPORARY_KEY` | Issuing the temporary key failed. |
| `ERR_VALIDATION`    | `jwt` field is blank.             |
---

## Activation

### `POST /pa/v3/activation/create`

Creates a new activation. The outer body is ECIES-encrypted in `APPLICATION_SCOPE`; the inner `activationData` field carries a further ECIES-encrypted layer 2 payload — see [Activation Layer 2 Schemas](#activation-layer-2-schemas).

- **Protocol versions:** 3.0, 3.1, 3.2, 3.3
- **Authentication:** none (application-scope encryption)

**Request** `ActivationLayer1Request` (decrypted from ECIES):

| Field                | Type                    | Required | Description                                                           |
|----------------------|-------------------------|----------|-----------------------------------------------------------------------|
| `type`               | `ActivationType`        | ✓        | Activation type: `CODE`, `CUSTOM`, or `RECOVERY`.                     |
| `identityAttributes` | `Map<String, String>`   | ✓        | Activation-type-specific identity attributes (e.g. `code`, `otp`).    |
| `customAttributes`   | `Map<String, Object>`   |          | Optional custom attributes passed to `CustomActivationProvider`.      |
| `activationData`     | `EciesEncryptedRequest` | ✓        | ECIES-encrypted layer 2 payload — see `ActivationLayer2Request (v3)`. |

**Response** `ActivationLayer1Response` (re-encrypted by ECIES):

| Field              | Type                     | Description                                                             |
|--------------------|--------------------------|-------------------------------------------------------------------------|
| `activationData`   | `EciesEncryptedResponse` | ECIES-encrypted layer 2 response — see `ActivationLayer2Response (v3)`. |
| `customAttributes` | `Map<String, Object>`    | Custom attributes returned by `CustomActivationProvider`.               |
| `userInfo`         | `Map<String, Object>`    | OIDC claims returned by `UserInfoProvider` (may be `null`).             |


| Error Code       | When                                                   |
|------------------|--------------------------------------------------------|
| `ERR_ENCRYPTION` | Encryption context missing or ECIES decryption failed. |
| `ERR_VALIDATION` | Required fields missing or invalid.                    |
---

### `POST /pa/v3/activation/status`

Returns the current activation status.

- **Protocol versions:** 3.0, 3.1, 3.2, 3.3
- **Authentication:** none

**Request** `ObjectRequest<ActivationStatusRequest>`:

| Field          | Type     | Required | Description                                          |
|----------------|----------|----------|------------------------------------------------------|
| `activationId` | `String` | ✓        | Activation ID.                                       |
| `challenge`    | `String` |          | 16-byte Base64 challenge for status blob encryption. |

**Response** `ObjectResponse<ActivationStatusResponse>`:

| Field                 | Type                  | Description                                             |
|-----------------------|-----------------------|---------------------------------------------------------|
| `activationId`        | `String`              | Activation ID.                                          |
| `encryptedStatusBlob` | `String`              | Encrypted activation status blob (Base64).              |
| `nonce`               | `String`              | Nonce used for status blob encryption (Base64).         |
| `customObject`        | `Map<String, Object>` | Custom object from `PowerAuthApplicationConfiguration`. |


| Error Code       | When                    |
|------------------|-------------------------|
| `ERR_VALIDATION` | `activationId` is null. |
---

### `POST /pa/v3/activation/remove`

Removes an activation. Requires a PowerAuth signature.

- **Protocol versions:** 3.0, 3.1, 3.2, 3.3
- **Authentication:** `X-PowerAuth-Authorization` header — `POSSESSION_KNOWLEDGE` or `POSSESSION_BIOMETRY` (or `POSSESSION` when `activation.remove.allow1fa=true`)
- **Request body:** none

**Response** `ObjectResponse<ActivationRemoveResponse>`:

| Field          | Type     | Description                   |
|----------------|----------|-------------------------------| 
| `activationId` | `String` | ID of the removed activation. |


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_ACTIVATION`     | Activation removal failed on the server.                    |
---

### `POST /pa/v3/activation/detail`

Returns the detail of the authenticated activation. Token-authenticated, response encrypted.

- **Protocol versions:** 3.0, 3.1, 3.2, 3.3
- **Authentication:** PowerAuth token (`POSSESSION_KNOWLEDGE` or `POSSESSION_BIOMETRY`)
- **Request body:** none (encrypted via `ACTIVATION_SCOPE`)

**Response** `ObjectResponse<ActivationDetailResponse>` (encrypted):

| Field            | Type     | Description                     |
|------------------|----------|---------------------------------| 
| `activationId`   | `String` | Activation ID.                  |
| `activationName` | `String` | Human-readable activation name. |


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_ACTIVATION`     | Activation detail query failed on the server.               |
---

### `POST /pa/v3/activation/rename`

Renames an activation. Signature-authenticated, response encrypted.

- **Protocol versions:** 3.0, 3.1, 3.2, 3.3
- **Authentication:** PowerAuth signature (`POSSESSION_KNOWLEDGE` or `POSSESSION_BIOMETRY`, resourceId `/pa/activation/rename`)

**Request** `ActivationRenameRequest`:

| Field            | Type     | Required | Description                  |
|------------------|----------|----------|------------------------------|
| `activationName` | `String` | ✓        | New name for the activation. |

**Response** `ObjectResponse<ActivationDetailResponse>` (encrypted):

| Field            | Type     | Description              |
|------------------|----------|--------------------------| 
| `activationId`   | `String` | Activation ID.           |
| `activationName` | `String` | Updated activation name. |


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_ACTIVATION`     | Rename operation failed on the server.                      |
| `ERR_VALIDATION`     | `activationName` is blank.                                  |
---

### `POST /pa/v4/activation/create`

Creates a new activation. The outer body is AEAD-encrypted in `APPLICATION_SCOPE`; the inner `activationData` field carries a further AEAD-encrypted layer 2 payload — see [Activation Layer 2 Schemas](#activation-layer-2-schemas).

- **Protocol versions:** 4.0
- **Authentication:** none (application-scope encryption)

**Request** `ActivationLayer1Request` (decrypted from AEAD):

| Field                | Type                   | Required | Description                                                          |
|----------------------|------------------------|----------|----------------------------------------------------------------------|
| `type`               | `ActivationType`       | ✓        | Activation type: `CODE`, `CUSTOM`, or `RECOVERY`.                    |
| `identityAttributes` | `Map<String, String>`  | ✓        | Activation-type-specific identity attributes.                        |
| `customAttributes`   | `Map<String, Object>`  |          | Optional custom attributes passed to `CustomActivationProvider`.     |
| `activationData`     | `AeadEncryptedRequest` | ✓        | AEAD-encrypted layer 2 payload — see `ActivationLayer2Request (v4)`. |

**Response** `ActivationLayer1Response` (re-encrypted by AEAD):

| Field              | Type                    | Description                                                            |
|--------------------|-------------------------|------------------------------------------------------------------------|
| `activationData`   | `AeadEncryptedResponse` | AEAD-encrypted layer 2 response — see `ActivationLayer2Response (v4)`. |
| `customAttributes` | `Map<String, Object>`   | Custom attributes returned by `CustomActivationProvider`.              |
| `userInfo`         | `Map<String, Object>`   | OIDC claims returned by `UserInfoProvider` (may be `null`).            |


| Error Code       | When                                                  |
|------------------|-------------------------------------------------------|
| `ERR_ENCRYPTION` | Encryption context missing or AEAD decryption failed. |
| `ERR_VALIDATION` | Required fields missing or invalid.                   |
---

### `POST /pa/v4/activation/status`

Returns the current activation status. Both request and response body are AEAD-encrypted in `ACTIVATION_SCOPE`. Allowed activation states: `ACTIVE`, `PENDING_COMMIT`, `BLOCKED`, `REMOVED`.

- **Protocol versions:** 4.0
- **Authentication:** none (activation-scope encryption)

**Request** `ActivationStatusRequest` (decrypted from AEAD): _(empty — activation is identified by the AEAD context)_

**Response** `ActivationStatusResponse` (re-encrypted by AEAD):

| Field                  | Type                  | Description                                                                                |
|------------------------|-----------------------|--------------------------------------------------------------------------------------------|
| `activationStatus`     | `String`              | Activation status: `CREATED`, `PENDING_COMMIT`, `ACTIVE`, `BLOCKED`, or `REMOVED`.         |
| `timestampBlockExpire` | `Long`                | Expiration of a temporary block in ms since Unix epoch; `null` if not temporarily blocked. |
| `customObject`         | `Map<String, Object>` | Custom object from `PowerAuthApplicationConfiguration`.                                    |


| Error Code       | When                                                  |
|------------------|-------------------------------------------------------|
| `ERR_ENCRYPTION` | Encryption context missing or AEAD decryption failed. |
---

### `POST /pa/v4/activation/remove`

Removes an activation. Requires a PowerAuth signature.

- **Protocol versions:** 4.0
- **Authentication:** `X-PowerAuth-Authorization` header — `POSSESSION_KNOWLEDGE` or `POSSESSION_BIOMETRY` (or `POSSESSION` when `activation.remove.allow1fa=true`)
- **Request body:** none

**Response** `ObjectResponse<ActivationRemoveResponse>`:

| Field          | Type     | Description                   |
|----------------|----------|-------------------------------|
| `activationId` | `String` | ID of the removed activation. |


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_ACTIVATION`     | Activation removal failed on the server.                    |
---

### `POST /pa/v4/activation/detail`

Returns the detail of the authenticated activation. Token-authenticated, response encrypted.

- **Protocol versions:** 4.0
- **Authentication:** PowerAuth token (`POSSESSION_KNOWLEDGE` or `POSSESSION_BIOMETRY`)
- **Request body:** none (encrypted via `ACTIVATION_SCOPE`)

**Response** `ObjectResponse<ActivationDetailResponse>` (encrypted):

| Field            | Type     | Description                     |
|------------------|----------|---------------------------------| 
| `activationId`   | `String` | Activation ID.                  |
| `activationName` | `String` | Human-readable activation name. |


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_ACTIVATION`     | Activation detail query failed on the server.               |
---

### `POST /pa/v4/activation/rename`

Renames an activation. Signature-authenticated, response encrypted.

- **Protocol versions:** 4.0
- **Authentication:** PowerAuth signature (`POSSESSION_KNOWLEDGE` or `POSSESSION_BIOMETRY`, resourceId `/pa/activation/rename`)

**Request** `ActivationRenameRequest`:

| Field            | Type     | Required | Description                  |
|------------------|----------|----------|------------------------------|
| `activationName` | `String` | ✓        | New name for the activation. |

**Response** `ObjectResponse<ActivationDetailResponse>` (encrypted):

| Field            | Type     | Description              |
|------------------|----------|--------------------------| 
| `activationId`   | `String` | Activation ID.           |
| `activationName` | `String` | Updated activation name. |


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_ACTIVATION`     | Rename operation failed on the server.                      |
| `ERR_VALIDATION`     | `activationName` is blank.                                  |
---

### `POST /pa/v4/activation/confirm`

Confirms an activation and optionally enables biometry. Requires `POSSESSION_KNOWLEDGE` signature. Allowed activation states: `ACTIVE`, `PENDING_COMMIT`.

- **Protocol versions:** 4.0
- **Authentication:** PowerAuth signature (`POSSESSION_KNOWLEDGE`, resourceId `/pa/activation/confirm`)

**Request** `ObjectRequest<ActivationConfirmRequest>`:

| Field            | Type      | Required | Description                                                         |
|------------------|-----------|----------|---------------------------------------------------------------------|
| `enableBiometry` | `boolean` |          | Whether to enable biometric authentication factor. Default `false`. |

**Response:** `Response` (empty success — just `status: "OK"`)


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_ACTIVATION`     | Confirm operation failed on the server.                     |
---

## Authentication / Signature Validation

### `GET|POST|PUT|DELETE /pa/v3/signature/validate`

Validates a PowerAuth signature on any request body.

- **Protocol versions:** 3.0, 3.1, 3.2, 3.3
- **Authentication:** `X-PowerAuth-Authorization` header — `POSSESSION`, `POSSESSION_KNOWLEDGE`, or `POSSESSION_BIOMETRY`; resourceId `/pa/signature/validate`
- **Request body:** any (included in the signed data)
- **Response:** `Response` (empty success)


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
---

### `GET|POST|PUT|DELETE /pa/v4/auth/validate`

Validates a PowerAuth authentication code on any request body.

- **Protocol versions:** 4.0
- **Authentication:** `X-PowerAuth-Authorization` header — `POSSESSION`, `POSSESSION_KNOWLEDGE`, or `POSSESSION_BIOMETRY`; resourceId `/pa/auth/validate`
- **Request body:** any (included in the signed data)
- **Response:** `Response` (empty success)


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
---

## Token-Based Authentication

### `POST /pa/v3/token/create`

Creates a simple authentication token. Request and response are ECIES-encrypted.

- **Protocol versions:** 3.0, 3.1, 3.2, 3.3
- **Authentication:** PowerAuth signature — `POSSESSION`, `POSSESSION_KNOWLEDGE`, or `POSSESSION_BIOMETRY`; resourceId `/pa/token/create`
- **Request body:** `EciesEncryptedRequest` _(opaque, encrypted by the client SDK)_
- **Response:** `EciesEncryptedResponse` _(opaque, decrypted by the client SDK; contains token ID and token secret)_


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_AUTHENTICATION` | Request body is null (`POWER_AUTH_REQUEST_INVALID`).        |
---

### `POST /pa/v3/token/remove`

Removes a simple authentication token.

- **Protocol versions:** 3.0, 3.1, 3.2, 3.3
- **Authentication:** PowerAuth signature — `POSSESSION`, `POSSESSION_KNOWLEDGE`, or `POSSESSION_BIOMETRY`; resourceId `/pa/token/remove`

**Request** `ObjectRequest<TokenRemoveRequest>`:

| Field     | Type     | Required | Description                |
|-----------|----------|----------|----------------------------|
| `tokenId` | `String` | ✓        | ID of the token to remove. |

**Response** `ObjectResponse<TokenRemoveResponse>`:

| Field     | Type     | Description              |
|-----------|----------|--------------------------| 
| `tokenId` | `String` | ID of the removed token. |


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_VALIDATION`     | `tokenId` is blank.                                         |
---

### `POST /pa/v4/token/create`

Creates a simple authentication token. Request and response are AEAD-encrypted.

- **Protocol versions:** 4.0
- **Authentication:** PowerAuth signature — `POSSESSION`, `POSSESSION_KNOWLEDGE`, or `POSSESSION_BIOMETRY`; resourceId `/pa/token/create`
- **Request body:** `AeadEncryptedRequest` _(opaque, encrypted by the client SDK)_
- **Response:** `AeadEncryptedResponse` _(opaque, decrypted by the client SDK; contains token ID and token secret)_


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_AUTHENTICATION` | Request body is null (`POWER_AUTH_REQUEST_INVALID`).        |
---

### `POST /pa/v4/token/remove`

Removes a simple authentication token.

- **Protocol versions:** 4.0
- **Authentication:** PowerAuth signature — `POSSESSION`, `POSSESSION_KNOWLEDGE`, or `POSSESSION_BIOMETRY`; resourceId `/pa/token/remove`

**Request** `ObjectRequest<TokenRemoveRequest>`:

| Field     | Type     | Required | Description               |
|-----------|----------|----------|---------------------------|
| `tokenId` | `String` | ✓        | ID of the token to remove. |

**Response** `ObjectResponse<TokenRemoveResponse>`:

| Field     | Type     | Description              |
|-----------|----------|--------------------------| 
| `tokenId` | `String` | ID of the removed token. |


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_VALIDATION`     | `tokenId` is blank.                                         |
---

## Secure Vault

### `POST /pa/v3/vault/unlock`

Unlocks the secure vault. The HTTP body is an `EciesEncryptedRequest`; the decrypted payload is `VaultUnlockRequestPayload`. The HTTP response is an `EciesEncryptedResponse`; the decrypted payload is `VaultUnlockResponsePayload`.

- **Protocol versions:** 3.0, 3.1, 3.2, 3.3
- **Authentication:** `X-PowerAuth-Authorization` header (any factor combination)

**Request payload** `VaultUnlockRequestPayload` (inside `EciesEncryptedRequest`):

| Field    | Type     | Description                                          |
|----------|----------|------------------------------------------------------| 
| `reason` | `String` | _(optional)_ Human-readable reason for vault unlock. |

**Response payload** `VaultUnlockResponsePayload` (inside `EciesEncryptedResponse`):

| Field                         | Type     | Description                              |
|-------------------------------|----------|------------------------------------------| 
| `encryptedVaultEncryptionKey` | `String` | Encrypted vault encryption key (Base64). |


| Error Code           | When                                                          |
|----------------------|---------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or header is malformed. |
| `ERR_SECURE_VAULT`   | Vault unlock failed on the server.                            |
---

### `POST /pa/v4/vault/unlock`

Unlocks the secure vault. The HTTP body is an `AeadEncryptedRequest`; the decrypted payload is `VaultUnlockRequestPayload`. The HTTP response is an `AeadEncryptedResponse`; the decrypted payload is `VaultUnlockResponsePayload`.

- **Protocol versions:** 4.0
- **Authentication:** `X-PowerAuth-Authorization` header (any factor combination)

**Request payload** `VaultUnlockRequestPayload` (inside `AeadEncryptedRequest`):

| Field           | Type     | Required | Description                                          |
|-----------------|----------|----------|------------------------------------------------------|
| `keyIdentifier` | `String` | ✓        | Identifier of the key to unlock.                     |
| `reason`        | `String` |          | _(optional)_ Human-readable reason for vault unlock. |

**Response payload** `VaultUnlockResponsePayload` (inside `AeadEncryptedResponse`):

| Field                | Type     | Description                    |
|----------------------|----------|--------------------------------| 
| `vaultEncryptionKey` | `String` | Vault encryption key (Base64). |


| Error Code           | When                                                          |
|----------------------|---------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or header is malformed. |
| `ERR_SECURE_VAULT`   | Vault unlock failed on the server.                            |
| `ERR_VALIDATION`     | `keyIdentifier` is blank.                                     |
---

## Biometry

### `POST /pa/v4/biometry/add`

Sets up biometric authentication. Request and response are AEAD-encrypted.

- **Protocol versions:** 4.0
- **Authentication:** PowerAuth signature — `POSSESSION_KNOWLEDGE`; resourceId `/pa/biometry/add`
- **Request body:** `AeadEncryptedRequest` _(opaque, encrypted by the client SDK; contains biometry factor key material)_
- **Response:** `AeadEncryptedResponse` _(opaque, decrypted by the client SDK)_


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_BIOMETRY`       | Biometry setup failed on the server.                        |
---

### `POST /pa/v4/biometry/remove`

Removes biometric authentication.

- **Protocol versions:** 4.0
- **Authentication:** PowerAuth signature — `POSSESSION`; resourceId `/pa/biometry/remove`
- **Request body:** none
- **Response:** `Response` (empty success)


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_BIOMETRY`       | Biometry removal failed on the server.                      |
---

## Password

### `POST /pa/v4/password/change`

Changes the knowledge factor (password / PIN). Request and response are AEAD-encrypted.

- **Protocol versions:** 4.0
- **Authentication:** PowerAuth signature — `POSSESSION_KNOWLEDGE`; resourceId `/pa/password/change`
- **Request body:** `AeadEncryptedRequest` _(opaque, encrypted by the client SDK; contains old and new password data)_
- **Response:** `AeadEncryptedResponse` _(opaque, decrypted by the client SDK)_


| Error Code            | When                                                        |
|-----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION`  | Authentication code validation failed or wrong factor type. |
| `ERR_PASSWORD_CHANGE` | Password change failed on the server.                       |
---

## Protocol Upgrade

### `POST /pa/v4/upgrade/start`

Starts the upgrade of an activation from protocol v3 to v4. Requires both `X-PowerAuth-Authorization` and `X-PowerAuth-Encryption` headers. The HTTP body is an `AeadEncryptedRequest`; the decrypted payload is `UpgradeRequestPayload`. The HTTP response is an `AeadEncryptedResponse`; the decrypted payload is `UpgradeResponsePayload`.

- **Protocol versions:** 4.0
- **Authentication:** PowerAuth signature — `POSSESSION_KNOWLEDGE`; resourceId `/pa/upgrade/start`

**Request payload** `UpgradeRequestPayload` (inside `AeadEncryptedRequest`):

| Field                 | Type                  | Required | Description                                                        |
|-----------------------|-----------------------|----------|--------------------------------------------------------------------|
| `sharedSecretRequest` | `SharedSecretRequest` | ✓        | KEM shared-secret request (algorithm + encapsulation keys).        |
| `devicePublicKeys`    | `DevicePublicKeys`    | ✓        | Device public keys for the upgraded protocol.                      |
| `enableBiometry`      | `boolean`             |          | Whether biometry should be enabled after upgrade. Default `false`. |

`SharedSecretRequest`:

| Field               | Type           | Required | Description                                                           |
|---------------------|----------------|----------|-----------------------------------------------------------------------|
| `algorithm`         | `String`       | ✓        | KEM algorithm identifier.                                             |
| `encapsulationKeys` | `List<String>` | ✓        | List of Base64-encoded client encapsulation keys (must not be empty). |

`DevicePublicKeys`:

| Field   | Type     | Required | Description                                                       |
|---------|----------|----------|-------------------------------------------------------------------|
| `ecdsa` | `String` | ✓        | Base64-encoded device ECDSA public key.                           |
| `mldsa` | `String` |          | Base64-encoded device ML-DSA public key (optional, post-quantum). |

**Response payload** `UpgradeResponsePayload` (inside `AeadEncryptedResponse`):

| Field                  | Type                   | Description                                              |
|------------------------|------------------------|----------------------------------------------------------|
| `sharedSecretResponse` | `SharedSecretResponse` | KEM shared-secret response (salt + encapsulated keys).   |
| `serverPublicKeys`     | `ServerPublicKeys`     | Server public keys for the upgraded protocol.            |
| `ctrData`              | `String`               | Base64-encoded counter data for the upgraded activation. |

`SharedSecretResponse`:

| Field              | Type           | Description                                      |
|--------------------|----------------|--------------------------------------------------| 
| `salt`             | `String`       | Base64-encoded KEM salt.                         |
| `encapsulatedKeys` | `List<String>` | List of Base64-encoded server-encapsulated keys. |

`ServerPublicKeys`:

| Field   | Type     | Description                                                            |
|---------|----------|------------------------------------------------------------------------| 
| `ecdsa` | `String` | Base64-encoded server ECDSA public key.                                |
| `mldsa` | `String` | Base64-encoded server ML-DSA public key (post-quantum; may be `null`). |


| Error Code           | When                                                                   |
|----------------------|------------------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type.            |
| `ERR_UPGRADE`        | Upgrade start failed (header invalid, version mismatch, server error). |
| `ERR_VALIDATION`     | Required payload fields missing.                                       |
---

### `POST /pa/v4/upgrade/confirm`

Confirms the upgrade of an activation from protocol v3 to v4.

- **Protocol versions:** 4.0
- **Authentication:** `X-PowerAuth-Authorization` header — `POSSESSION`; resourceId `/pa/upgrade/confirm`
- **Request body:** none
- **Response:** `Response` (empty success)


| Error Code           | When                                                        |
|----------------------|-------------------------------------------------------------|
| `ERR_AUTHENTICATION` | Authentication code validation failed or wrong factor type. |
| `ERR_UPGRADE`        | Upgrade confirmation failed (header invalid, server error). |
---

## User Info

### `POST /pa/v3/user/info`
### `POST /pa/v4/user/info`

Returns OIDC-style user info claims for the authenticated activation owner. Both request and response are AEAD-encrypted in `ACTIVATION_SCOPE`. Served by the `UserInfoProvider` SPI.

- **Protocol versions:** 3.0, 3.1, 3.2, 3.3, 4.0
- **Authentication:** activation-scope encryption (activation must be valid)

**Request** `UserInfoRequest` (decrypted from AEAD): _(empty — no selectable claims filtering at this time)_

**Response** `Map<String, Object>` (re-encrypted by AEAD): OIDC standard claims. Common fields:

| Claim          | Type     | Description                   |
|----------------|----------|-------------------------------| 
| `sub`          | `String` | Subject identifier (user ID). |
| `name`         | `String` | Full name.                    |
| `given_name`   | `String` | Given (first) name.           |
| `family_name`  | `String` | Family name.                  |
| `email`        | `String` | Email address.                |
| `phone_number` | `String` | Phone number.                 |

Additional claims may be provided by the application's `UserInfoProvider` implementation.


| Error Code      | When                                            |
|-----------------|-------------------------------------------------|
| `ERR_USER_INFO` | `UserInfoProvider` failed or returned an error. |
---

## Secure Configuration

### `POST /pa/v4/config/application`

Fetches configuration items visible in the **application scope** (non-personalized, shared by all activations). The request and response body are AEAD-encrypted in `APPLICATION_SCOPE`.

- **Protocol versions:** 4.0
- **Authentication:** none (application-scope encryption)
- **Request body:** empty encrypted body

**Response** `ConfigResponse` (re-encrypted by AEAD):

| Field    | Type               | Description                  |
|----------|--------------------|------------------------------|
| `config` | `List<ConfigItem>` | List of configuration items. |

`ConfigItem`:

| Field   | Type          | Description                                            |
|---------|---------------|--------------------------------------------------------| 
| `key`   | `String`      | Configuration item key.                                |
| `value` | `Object`      | Configuration item value; a scalar or a nested object. |
| `scope` | `ConfigScope` | Scope: `APPLICATION` or `ACTIVATION`.                  |


| Error Code   | When                                              |
|--------------|---------------------------------------------------|
| `ERR_CONFIG` | Configuration fetch from PowerAuth Server failed. |
---

### `POST /pa/v4/config/activation`

Fetches configuration items visible in the **activation scope** (personalized, post-activation). The request and response body are AEAD-encrypted in `ACTIVATION_SCOPE`.

- **Protocol versions:** 4.0
- **Authentication:** activation-scope encryption (activation must be valid)
- **Request body:** empty encrypted body

**Response** `ConfigResponse` (re-encrypted by AEAD): same structure as above. May include items of both `APPLICATION` and `ACTIVATION` scope.


| Error Code   | When                                              |
|--------------|---------------------------------------------------|
| `ERR_CONFIG` | Configuration fetch from PowerAuth Server failed. |
---

## Activation Layer 2 Schemas

The `activationData` field in `ActivationLayer1Request` / `ActivationLayer1Response` carries a second encrypted envelope whose plaintext is the layer 2 request/response object. These are produced and consumed by the client SDK; the server decrypts and re-encrypts them internally.

### `ActivationLayer2Request` (v3, inside `EciesEncryptedRequest`)

| Field             | Type     | Description                                                               |
|-------------------|----------|---------------------------------------------------------------------------| 
| `devicePublicKey` | `String` | Base64-encoded device public key.                                         |
| `activationOtp`   | `String` | _(optional)_ Additional activation OTP for extra-factor activation types. |
| `activationName`  | `String` | _(optional)_ Human-readable name for the activation.                      |
| `extras`          | `String` | _(optional)_ Arbitrary extra data stored with the activation.             |
| `platform`        | `String` | _(optional)_ User device platform (e.g. `ios`, `android`).                |
| `deviceInfo`      | `String` | _(optional)_ Human-readable device model / OS information.                |

### `ActivationLayer2Response` (v3, inside `EciesEncryptedResponse`)

| Field             | Type     | Description                          |
|-------------------|----------|--------------------------------------| 
| `activationId`    | `String` | Assigned activation ID (UUID).       |
| `serverPublicKey` | `String` | Base64-encoded server public key.    |
| `ctrData`         | `String` | Base64-encoded initial counter data. |

---

### `ActivationLayer2Request` (v4, inside `AeadEncryptedRequest`)

| Field                 | Type                  | Required | Description                                                   |
|-----------------------|-----------------------|----------|---------------------------------------------------------------|
| `sharedSecretRequest` | `SharedSecretRequest` |          | KEM shared-secret request — see `SharedSecretRequest` above.  |
| `devicePublicKeys`    | `DevicePublicKeys`    |          | Device public keys — see `DevicePublicKeys` above.            |
| `activationOtp`       | `String`              |          | _(optional)_ Additional activation OTP.                       |
| `activationName`      | `String`              |          | _(optional)_ Human-readable name for the activation.          |
| `extras`              | `String`              |          | _(optional)_ Arbitrary extra data stored with the activation. |
| `platform`            | `String`              |          | _(optional)_ User device platform (e.g. `ios`, `android`).    |
| `deviceInfo`          | `String`              |          | _(optional)_ Human-readable device model / OS information.    |

### `ActivationLayer2Response` (v4, inside `AeadEncryptedResponse`)

| Field                  | Type                   | Description                                                    |
|------------------------|------------------------|----------------------------------------------------------------|
| `sharedSecretResponse` | `SharedSecretResponse` | KEM shared-secret response — see `SharedSecretResponse` above. |
| `serverPublicKeys`     | `ServerPublicKeys`     | Server public keys — see `ServerPublicKeys` above.             |
| `activationId`         | `String`               | Assigned activation ID (UUID).                                 |
| `ctrData`              | `String`               | Base64-encoded initial counter data.                           |
