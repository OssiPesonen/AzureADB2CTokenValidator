<?php

namespace AzureADB2CTokenValidator;

use AzureADB2CTokenValidator\Exceptions\InvalidClaimException;
use AzureADB2CTokenValidator\Exceptions\MissingResponseException;
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
    protected array $openIdConfiguration;

    /** @var string Azure AD B2C Tenant name found in domain (tenant.onmicrosoft.com) */
    public string $tenant;

    /** @var string User flow name */
    private string $policy;

    /** @var string Default Open ID Connect version */
    public string $defaultEndPointVersion = '2.0';

    /** @var string Azure AD B2C App Client ID */
    private string $clientId;

    /** @var ?PublicKey $publicKey Public key containing the kid, modulus, exponent etc. */
    private ?PublicKey $publicKey;

    /** @var int Leeway given for JWT to correct possible errors in having Azure tokens not match server time */
    public static $leeway = 0;

    /** @var File */
    private File $file;

    public function __construct(string $tenant, string $policy, string $clientId, ?File $file)
    {
        $this->policy = $policy;
        $this->clientId = $clientId;
        $this->tenant = strtolower($tenant);
        $this->publicKey = null;
        $this->file = $file ?? File::getInstance();
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
     * @throws MissingResponseException
     */
    private function getTenantDetails(string $tenant)
    {
        return $this->getOpenIdConfiguration($tenant, $this->defaultEndPointVersion);
    }

    /**
     * Get access token header payload
     *
     * @param string $accessToken
     * @return object
     */
    public function getAccessTokenHeader(string $accessToken): object
    {
        list($header, ,) = explode('.', $accessToken);
        return json_decode(base64_decode($header));
    }

    /**
     * Return the key ID used to sign this access token
     *
     * @param string $accessToken
     * @return string|null
     */
    public function getAccessTokenKid(string $accessToken): ?string
    {
        $headers = $this->getAccessTokenHeader($accessToken);
        return $headers->kid ?? null;
    }

    /**
     * Validates provided access token
     *
     * @param string $accessToken Json Web Token
     * @return array Access token claims ie. aud, iss, exp etc.
     * @throws MissingResponseException|Exception
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

        # Set a bit of leeway
        if (self::$leeway !== 0) {
            JWT::$leeway = self::$leeway;
        }

        $claims = (array)JWT::decode($accessToken, $publicKey, [$headerPayload->alg]);
        $this->validateTokenClaims($claims);

        return $claims;
    }

    /**
     * Returns the public key data for provided key ID
     *
     * @param string $kid
     * @return PublicKey|null
     * @throws MissingResponseException
     */
    private function getJwtVerificationKey(string $kid): ?PublicKey
    {
        $keys = [];
        $discoveredKeys = $this->file->request($this->getDiscoveryUrl());

        if (is_array($discoveredKeys->keys)) {
            foreach ($discoveredKeys->keys as $key) {
                $keys[$key->kid] = $key;
            }
        }

        if ($keys[$kid]) {
            $this->publicKey = new PublicKey((array)$keys[$kid]);
        }

        return $this->publicKey;
    }

    /**
     * Return public key object
     *
     * @return PublicKey|null
     */
    public function getPublicKey(): ?PublicKey
    {
        return $this->publicKey;
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

        // Additional validation is being performed in firebase/JWT itself
        if ($tokenClaims['nbf'] > (time() - self::$leeway)) {
            throw new InvalidClaimException('The id_token is not valid yet. Validity begins ' . date('Y-m-d H:i:s',
                    $tokenClaims['nbf'] . '. Time now ' . date('Y-m-d H:i:s', time())));
        }

        if ($tokenClaims['exp'] < (time() + self::$leeway)) {
            throw new InvalidClaimException('The id_token has expired. Token has expired at ' . date('Y-m-d H:i:s',
                    $tokenClaims['exp'] . '. Time now ' . date('Y-m-d H:i:s', time())));
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
     *
     * @throws MissingResponseException
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
            $response = $this->file->request($openIdConfigurationUri);
            $this->openIdConfiguration[$tenant][$version] = $response;
        }

        return $this->openIdConfiguration[$tenant][$version];
    }
}