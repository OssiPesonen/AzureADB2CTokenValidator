# AzureADB2CTokenValidator

A simple implementation of Azure AD B2C token validation with PHP. The trick with AD B2C is to fetch the public key of your tenant and calculate a public key with the modulus and exponent. For this we use the PublicKeyLoader from phpseclib3. 

## Requirements

- PHP 7.1

## Installation

```
composer require ossipesonen/azureadb2ctokenvalidator
```

## How to use

```php
<?php

use AzureADB2CTokenValidator;

$token = "";
$validator = new AzureADB2CTokenValidator\Validator("tenant", "B2C_1_SignUpSignIn", "clientId");
$claims = $validator->validateToken($token);
```

Very simple. Firebase's JWT package already verifies the token's signature and expiration.

## Caching

The public keys in Azure rotate every 24 hours. It is highly recommended to cache the key somewhere nearby and use that if the `kid` (key id) value still matches. You can do this by providing the cached key payload (JSON format)

```php

use AzureADB2CTokenValidator;

# Requires all properties to exist
$cachedKey = new AzureADB2CTokenValidator\PublicKey(["kid" => "", "..."]);

$accessToken = "...";
$verified = new AzureADB2CTokenValidator\Validator("tenant", "B2C_1_SignUpSignIn", "ClientId");
$kid = $verified->getAccessTokenKid($accessToken);

if ($kid === $cachedKey->kid) {
    $claims = $this->validateToken($accessToken, $cachedKey);
}
```