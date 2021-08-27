<?php

require_once('vendor/autoload.php');

use Firebase\JWT\JWT;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;

class AzureADB2CTokenVerifier
{
    const ENDPOINT_VERSION_2_0 = '2.0';

    protected $openIdConfiguration;

    public $tenant = 'common';
    /**
     * @var string
     */
    private $policy;

    public $defaultEndPointVersion = self::ENDPOINT_VERSION_2_0;
    /**
     * @var string
     */
    private $clientId;

    public function __construct(string $tenant, string $policy, string $clientId)
    {
        $this->policy = $policy;
        $this->tenant = $tenant;
        $this->clientId = $clientId;
    }

    private function getDiscoveryUrl(): string
    {
        return "https://{$this->tenant}.b2clogin.com/{$this->tenant}.onmicrosoft.com/{$this->policy}/discovery/v2.0/keys";
    }

    private function getOpenIdConfigurationUrl(string $version): string
    {
        return "https://{$this->tenant}.b2clogin.com/{$this->tenant}.onmicrosoft.com/{$this->policy}/v${version}/.well-known/openid-configuration";
    }

    public function validateAccessToken(string $accessToken): array
    {
        list($header, ,) = explode('.', $accessToken);
        $headerPayload = json_decode(base64_decode($header));
        $key = $this->getJwtVerificationKey($headerPayload->kid);
        $claims = null;

        if ($key) {
            $publicKey = $this->generatePublicKeyFromModulusAndExponent($key->n, $key->e);
            $claims = (array)JWT::decode($accessToken, $publicKey, [$headerPayload->alg]);
            $this->validateTokenClaims($claims);
        }

        return $claims;
    }

    private function getJwtVerificationKey(string $kid)
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

        return $keys[$kid] ?? null;
    }

    private function generatePublicKeyFromModulusAndExponent(string $modulus, string $exponent): string
    {
        return PublicKeyLoader::load([
            'n' => new BigInteger($this->base64UrlDecode($modulus), 256),
            'e' => new BigInteger($this->base64UrlDecode($exponent), 256),
        ]);
    }

    private function base64UrlDecode(string $data): string
    {
        $base64data = strtr($data, '-_', '+/');
        return base64_decode($base64data);
    }

    private function validateTokenClaims($tokenClaims)
    {
        if ($this->clientId !== $tokenClaims['aud']) {
            throw new \RuntimeException('The client_id / audience is invalid!');
        }

        if ($tokenClaims['nbf'] > time() || $tokenClaims['exp'] < time()) {
            // Additional validation is being performed in firebase/JWT itself
            throw new \RuntimeException('The id_token is invalid!');
        }

        if ('common' == $this->tenant) {
            $this->tenant = $tokenClaims['tid'];
        }

        $tenant = $this->getTenantDetails($this->tenant);

        if ($tokenClaims['iss'] != $tenant['issuer']) {
            throw new \RuntimeException('Invalid token issuer (tokenClaims[iss]' . $tokenClaims['iss'] . ', tenant[issuer] ' . $tenant['issuer'] . ')!');
        }
    }

    public function getTenantDetails($tenant)
    {
        return $this->getOpenIdConfiguration($tenant, $this->defaultEndPointVersion);
    }

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
            $response = json_decode($request, true);
            $this->openIdConfiguration[$tenant][$version] = $response;
        }

        return $this->openIdConfiguration[$tenant][$version];
    }
}
