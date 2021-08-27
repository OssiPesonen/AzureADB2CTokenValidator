# AzureADB2CTokenValidator

A simple implementation of Azure AD B2C token validation with PHP. The trick with AD B2C is to fetch the public key of your tenant and calculate a public key with the modulus and exponent. For this we use the PublicKeyLoader from phpseclib3. 

## Example:

```php
$verified = new AzureADB2CTokenVerifier("tenant", "B2C_1_SignUpSignIn", "ClientId");
$claims = $verified->validateAccessToken("...");
```

Very simple. Firebase's JWT package already verifies the token's signature against the provided key.

## Due note

The public key rotates nearly every 24 hours. It's highly recommended to cache the key and use that if the `kid` value hasn't changed. Otherwise you can update the key and cache it again for 24 hours.

