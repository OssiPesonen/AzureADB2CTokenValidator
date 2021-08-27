<?php

namespace AzureADB2CTokenValidator\Contracts;

use AzureADB2CTokenValidator\PublicKey;

interface ValidatorInterface {
    public function getTenantDetails(string $tenant);

    public function getAccessTokenKid(string $accessToken);

    public function getAccessTokenHeader(string $accessToken);

    public function validateToken(string $accessToken, ?PublicKey $key);
}