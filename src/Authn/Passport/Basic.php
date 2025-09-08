<?php

namespace Obman\LaravelApiAuthClient\Authn\Passport;

use Obman\LaravelApiAuthClient\Authn\BaseAuthn;
use Obman\LaravelApiAuthClient\DTO\AuthnPayload;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\Exceptions\UserMissingException;
use Obman\LaravelApiAuthClient\Services\TokenService;

class Basic extends BaseAuthn
{
    public function authenticate(AuthnPayload $payload): AuthnResult
    {
        if (empty($payload->user)) {
            throw new UserMissingException();
        }

        $this->clearRateLimitingAttempts();
        $tokenService = new TokenService($payload->user);

        return new AuthnResult(
            bearer: $payload->tokens['access_token'],
            expiresIn: now('UTC')->addSeconds($payload->tokens['expires_in']),
            maxAge: $payload->tokens['expires_in'],
            refresh: $tokenService->getRefreshCookieToken($payload->tokens['refresh_token']),
            csrf: $tokenService->getCsrfCookieToken(),
            user: $payload->user
        );
    }

    public function refresh(AuthnPayload $payload): AuthnResult
    {
        $this->clearRateLimitingAttempts();
        $tokenService = new TokenService(null);

        return new AuthnResult(
            bearer: $payload->tokens['access_token'],
            expiresIn: now('UTC')->addSeconds($payload->tokens['expires_in']),
            maxAge: $payload->tokens['expires_in'],
            refresh: $tokenService->getRefreshCookieToken($payload->tokens['refresh_token']),
            csrf: $tokenService->getCsrfCookieToken(),
            user: null
        );
    }
}
