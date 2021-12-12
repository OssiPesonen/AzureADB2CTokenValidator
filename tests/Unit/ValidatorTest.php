<?php

use AzureADB2CTokenValidator\Validator;

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