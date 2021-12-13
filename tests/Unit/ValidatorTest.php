<?php

use AzureADB2CTokenValidator\Exceptions\InvalidKidException;
use AzureADB2CTokenValidator\File;
use AzureADB2CTokenValidator\PublicKey;
use AzureADB2CTokenValidator\Validator;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;

/**
 * Reads the modulus and exponent from a private key,
 * to generate public key payload like Azure does
 *
 * @param string $key
 * @return array
 */
function getModulusAndExponentFromPrivateKey(string $key): array
{
    $data = openssl_pkey_get_private($key);
    $data = openssl_pkey_get_details($data);
    return [base64_encode($data['rsa']['n']), base64_encode($data['rsa']['e'])];
}

/**
 * Creates a JWT for testing
 *
 * @param string $clientId
 * @return array
 * @throws Exception
 */
function createJwt(string $clientId, int $notBefore = -60, int $expiration = 3600)
{
    # Self generated private and public key pair to sign JWT
    $privateKey = @file_get_contents(dirname(__DIR__) . '/resources/keys/private.key');
    $publicKey = @file_get_contents(dirname(__DIR__) . '/resources/keys/public.key');

    if (!$privateKey || !$publicKey) {
        throw new Exception("Missing private or public key. Please generate keys for testing.");
    }

    # Adjust eligibility
    $created = time() + $notBefore;
    $kid = base64_encode(openssl_random_pseudo_bytes(32));

    # JWT payload
    $payload = [
        "exp"       => time() + $expiration,
        "nbf"       => $created,
        "ver"       => "1.0",
        "iss"       => "https://demo.b2clogin.com/demo-client-id/v2.0/",
        "sub"       => "batman",
        "aud"       => $clientId,
        "nonce"     => "ghi",
        "iat"       => $created,
        "auth_time" => $created,
        "name"      => "John Doe",
        "emails"    => [
            "john.doe@example.com"
        ],
        "tfp"       => "B2C_1_SignUpSignIn",
        "at_hash"   => base64_encode(openssl_random_pseudo_bytes(32))
    ];

    # Read the modulus and exponent off private key for JWT decoding. We do this, because
    # we can't get the private key from Azure, and we don't want to create an integration test
    # with a live B2C account.
    list($modulus, $exponent) = getModulusAndExponentFromPrivateKey($privateKey);

    $jwt = JWT::encode($payload, $privateKey, 'RS256', null, ['kid' => $kid]);

    # Pass the public key to validator. Normally this would either be stored locally
    # for a short period of time, or fetched from Azure kid doesn't match, or cache is expired
    $publicKey = new PublicKey([
        'n'   => $modulus,
        'e'   => $exponent,
        'kid' => $kid,
        'nbf' => $created,
        'use' => 'sig',
        'kty' => 'RSA',
    ]);

    return [
        'privateKey' => $privateKey,
        'publicKey'  => $publicKey,
        'jwt'        => $jwt,
        'modulus'    => $modulus,
        'exponent'   => $exponent,
        'payload'    => $payload,
    ];
}

it('Should decode JWT header correctly', function () {
    $validator = new Validator('abc', 'sign_in', 'clientId');
    $dummyJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    expect($validator->getAccessTokenHeader($dummyJwt))->toEqual((object)['alg' => 'HS256', 'typ' => 'JWT']);
});

it('Should return NULL for missing kid', function () {
    $validator = new Validator('abc', 'sign_in', 'clientId');
    $dummyJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    expect($validator->getAccessTokenKid($dummyJwt))->toBeNull();
});

it('Should return abc for kid', function () {
    $validator = new Validator('abc', 'sign_in', 'clientId');
    $dummyJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8Rnj5RHrgEm8gikgfU8Sxw8p7utNntBDE_U6m4Lg5_s";
    expect($validator->getAccessTokenKid($dummyJwt))->toEqual("abc");
});

it('Should validate JWT successfully', function () {
    $tenant = "batcave";
    $policy = 'sign_in';
    $clientId = 'abc';

    $testData = createJwt($clientId);
    $payload = $testData['payload'];

    # Mock the HTTP request to fetch tenant details
    $file = $this->createMock(File::class);
    $file->expects($this->once())
        ->method('request')
        ->with(
            $this->equalTo("https://$tenant.b2clogin.com/$tenant.onmicrosoft.com/$policy/v2.0/.well-known/openid-configuration")
        )
        ->willReturn((object)['issuer' => 'https://demo.b2clogin.com/demo-client-id/v2.0/']);

    $validator = new Validator($tenant, $policy, $clientId, $file);


    $claims = $validator->validateToken($testData['jwt'], $testData['publicKey']);

    expect($claims['aud'])->toEqual($payload['aud']);
    expect($claims['iss'])->toEqual($payload['iss']);
    expect($claims['exp'])->toEqual($payload['exp']);
    expect($claims['nbf'])->toEqual($payload['nbf']);
});

it('Should validate JWT successfully after fetching public key data', function () {
    $tenant = "batcave";
    $policy = 'sign_in';
    $clientId = 'abc';

    $testData = createJwt($clientId);
    $payload = $testData['payload'];

    # Mock the HTTP request to fetch keys and then tenant details
    $file = $this->createMock(File::class);
    $file->expects($this->exactly(2))
        ->method('request')
        ->withConsecutive(
            [$this->equalTo("https://$tenant.b2clogin.com/$tenant.onmicrosoft.com/$policy/discovery/v2.0/keys")],
            [$this->equalTo("https://$tenant.b2clogin.com/$tenant.onmicrosoft.com/$policy/v2.0/.well-known/openid-configuration")]
        )
        ->will($this->onConsecutiveCalls(
            (object)[
                'keys' => [
                    (object)[
                        'kid' => $testData['publicKey']->kid,
                        'nbf' => $testData['publicKey']->nbf,
                        'use' => $testData['publicKey']->use,
                        'kty' => $testData['publicKey']->kty,
                        'e'   => $testData['publicKey']->e,
                        'n'   => $testData['publicKey']->n,
                    ]
                ]
            ],
            (object)['issuer' => 'https://demo.b2clogin.com/demo-client-id/v2.0/']
        ));

    $validator = new Validator($tenant, $policy, $clientId, $file);
    $claims = $validator->validateToken($testData['jwt']);

    expect($claims['aud'])->toEqual($payload['aud']);
    expect($claims['iss'])->toEqual($payload['iss']);
    expect($claims['exp'])->toEqual($payload['exp']);
    expect($claims['nbf'])->toEqual($payload['nbf']);
});

it('Should expect InvalidKidException when no keys are found over the web', function () {
    $tenant = "batcave";
    $policy = 'sign_in';
    $clientId = 'abc';

    $testData = createJwt($clientId);

    # Mock the HTTP request to fetch keys and then tenant details
    $file = $this->createMock(File::class);
    $file->expects($this->once())
        ->method('request')
        ->with(
            $this->equalTo("https://$tenant.b2clogin.com/$tenant.onmicrosoft.com/$policy/discovery/v2.0/keys"),
        )
        ->willReturn(null);

    $validator = new Validator($tenant, $policy, $clientId, $file);
    $validator->validateToken($testData['jwt']);
})->throws(InvalidKidException::class);

it('Should fail decoding with an invalid public key', function () {
    $tenant = "batcave";
    $policy = 'sign_in';
    $clientId = 'abc';

    $testData = createJwt($clientId);

    # Fiddle with the public key a little bit
    $publicKey = $testData['publicKey'];
    $publicKey->e = 23938;

    $validator = new Validator($tenant, $policy, $clientId);
    $validator->validateToken($testData['jwt'], $publicKey);
})->throws(SignatureInvalidException::class);

it('Should fail decoding with an ineligible token', function () {
    $tenant = "batcave";
    $policy = 'sign_in';
    $clientId = 'abc';

    # Adjust the nbf little bit into the future
    $testData = createJwt($clientId, 600);

    $validator = new Validator($tenant, $policy, $clientId);
    $validator->validateToken($testData['jwt'], $testData['publicKey']);
})->throws(BeforeValidException::class);

it('Should fail decoding with an expired token', function () {
    $tenant = "batcave";
    $policy = 'sign_in';
    $clientId = 'abc';

    # Adjust the nbf little bit into the future
    $testData = createJwt($clientId, -10, -600);

    $validator = new Validator($tenant, $policy, $clientId);
    $validator->validateToken($testData['jwt'], $testData['publicKey']);
})->throws(ExpiredException::class);

it('Should be able to get public key', function () {
    $tenant = "batcave";
    $policy = 'sign_in';
    $clientId = 'abc';

    # Adjust the nbf little bit into the future
    $testData = createJwt($clientId, -10, -600);

    $validator = new Validator($tenant, $policy, $clientId);
    $publicKey = $validator->getPublicKey();
    $validator->validateToken($testData['jwt'], $testData['publicKey']);

    expect($publicKey->e)->toEqual($testData['publicKey']->e);
    expect($publicKey->n)->toEqual($testData['publicKey']->n);
    expect($publicKey->kid)->toEqual($testData['publicKey']->kid);
    expect($publicKey->nbf)->toEqual($testData['publicKey']->nbf);
})->throws(ExpiredException::class);