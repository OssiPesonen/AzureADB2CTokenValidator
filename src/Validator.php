<?php

namespace AzureADB2CTokenValidator;

use AzureADB2CTokenValidator\Exceptions\InvalidClaimException;
use Exception;
use Firebase\JWT\JWT;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;
use AzureADB2CTokenValidator\Contracts\ValidatorInterface;
use AzureADB2CTokenValidator\Exceptions\InvalidKidException;

/**
 * Validator for Azure AD B2C access tokens
 * @see https://docs.microsoft.com/en-us/azure/active-directory-b2c/tokens-overview#validation
 *
 * Class Validator
 * @package AzureADB2CTokenValidator
 */
class Validator implements ValidatorInterface
{
    /** @var array Open ID Connect metadata document */
    protected $openIdConfiguration;

    /** @var string Azure AD B2C Tenant name found in domain (tenant.onmicrosoft.com) */
    public $tenant;

    /** @var string User flow name */
    private $policy;

    /** @var string Default Open ID Connect version */
    public $defaultEndPointVersion = '2.0';

    /** @var string Azure AD B2C App Client ID */
    private $clientId;

    public function __construct(string $tenant, string $policy, string $clientId)
    {
        $this->policy = $policy;
        $this->clientId = $clientId;
        $this->tenant = strtolower($tenant);
    }

    /**
     * Return JSON document containing public key information.
     *
     * It is recommended to fetch this dynamically from OpenID Connect metadata endpoint,
     * but we don't want to make another network call.
     *
     * @return string
     */
    private function getDiscoveryUrl(): string
    {
        return "https://{$this->tenant}.b2clogin.com/{$this->tenant}.onmicrosoft.com/{$this->policy}/discovery/v2.0/keys";
    }

    /**
     * Return the full Open ID Connect metadata document URL
     *
     * @param string $version
     * @return string
     */
    private function getOpenIdConfigurationUrl(string $version): string
    {
        return "https://{$this->tenant}.b2clogin.com/{$this->tenant}.onmicrosoft.com/{$this->policy}/v${version}/.well-known/openid-configuration";
    }

    /**
     * Return tenant details
     *
     * @param string $tenant
     * @return mixed
     */
    public function getTenantDetails(string $tenant)
    {
        return $this->getOpenIdConfiguration($tenant, $this->defaultEndPointVersion);
    }

    /**
     * Get access token header payload
     *
     * @param string $accessToken
     * @return mixed
     */
    public function getAccessTokenHeader(string $accessToken)
    {
        list($header, ,) = explode('.', $accessToken);
        return json_decode(base64_decode($header));
    }

    /**
     * Return the key ID used to sign this access token
     *
     * @param string $accessToken
     * @return mixed
     */
    public function getAccessTokenKid(string $accessToken)
    {
        return $this->getAccessTokenHeader($accessToken)->kid;
    }

    /**
     * Validates provided access token
     *
     * @param string $accessToken Json Web Token
     * @return array Access token claims ie. aud, iss, exp etc.
     * @throws Exception
     */
    public function validateToken(string $accessToken, PublicKey $key = null): array
    {
        $headerPayload = $this->getAccessTokenHeader($accessToken);

        if (!$key) {
            # Fetch the public key based on token header kid (key ID) value
            $key = $this->getJwtVerificationKey($headerPayload->kid);

            if (!$key) {
                throw new InvalidKidException("No key found. Invalid kid provided.");
            }
        }

        $publicKey = $this->generatePublicKeyFromModulusAndExponent($key->n, $key->e);
        $claims = (array)JWT::decode($accessToken, $publicKey, [$headerPayload->alg]);
        $this->validateTokenClaims($claims);

        return $claims;
    }

    /**
     * Returns the public key data for provided key ID
     *
     * @param string $kid
     * @return PublicKey|null
     */
    private function getJwtVerificationKey(string $kid): ?PublicKey
    {
        $keys = [];
        $discoveredKeys = file_get_contents($this->getDiscoveryUrl());

        if (!$discoveredKeys) {
            throw new Exception("Invalid tenant information provided");
        }

        $discoveredKeys = json_decode($discoveredKeys);

        if (is_array($discoveredKeys->keys)) {
            foreach ($discoveredKeys->keys as $key) {
                $keys[$key->kid] = $key;
            }
        }

        return $keys[$kid] ? new PublicKey((array)$keys[$kid]) : null;
    }

    /**
     * Generate a public key from modulus (n) and exponent (e)
     *
     * @param string $modulus
     * @param string $exponent
     *
     * @return string
     */
    private function generatePublicKeyFromModulusAndExponent(string $modulus, string $exponent): string
    {
        return PublicKeyLoader::load([
            'n' => new BigInteger($this->base64UrlDecode($modulus), 256),
            'e' => new BigInteger($this->base64UrlDecode($exponent), 256),
        ]);
    }

    /**
     * Base 64 URL decode specific string while replacing underscore
     *
     * @param string $data
     * @return string
     */
    private function base64UrlDecode(string $data): string
    {
        $base64data = strtr($data, '-_', '+/');
        return base64_decode($base64data);
    }

    /**
     * Validate token claims against tenant information
     *
     * @param array $tokenClaims
     * @throws InvalidClaimException
     */
    private function validateTokenClaims(array $tokenClaims)
    {
        if ($this->clientId !== $tokenClaims['aud']) {
            throw new InvalidClaimException('The client_id or audience is invalid');
        }

        if ($tokenClaims['nbf'] > time() || $tokenClaims['exp'] < time()) {
            // Additional validation is being performed in firebase/JWT itself
            throw new InvalidClaimException('The id_token is invalid');
        }

        $tenant = $this->getTenantDetails($this->tenant);

        if ($tokenClaims['iss'] != $tenant->issuer) {
            throw new InvalidClaimException('Invalid token issuer (tokenClaims[iss]' . $tokenClaims['iss'] . ', tenant[issuer] ' . $tenant->issuer . ')');
        }
    }

    /**
     * Return Open ID Connect metadata
     *
     * @param string $tenant
     * @param string $version
     * @return mixed
     */
    protected function getOpenIdConfiguration(string $tenant, string $version)
    {
        if (!is_array($this->openIdConfiguration)) {
            $this->openIdConfiguration = [];
        }

        if (!array_key_exists($tenant, $this->openIdConfiguration)) {
            $this->openIdConfiguration[$tenant] = [];
        }

        if (!array_key_exists($version, $this->openIdConfiguration[$tenant])) {
            $openIdConfigurationUri = $this->getOpenIdConfigurationUrl($version);
            $request = file_get_contents($openIdConfigurationUri);
            $response = json_decode($request);
            $this->openIdConfiguration[$tenant][$version] = $response;
        }

        return $this->openIdConfiguration[$tenant][$version];
    }
}