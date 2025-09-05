<?php

namespace Obman\LaravelApiAuthClient\Authn\Passport;

use Obman\LaravelApiAuthClient\Authn\BaseAuthn;
use Obman\LaravelApiAuthClient\Exceptions\CredentialsMissingException;
use Obman\LaravelApiAuthClient\DTO\AuthnPayload;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\Services\TokenService;
use App\Models\User;

class Basic extends BaseAuthn
{
    public function authenticate(AuthnPayload $payload): AuthnResult
    {
        if (empty($payload->user)) {
            throw new CredentialsMissingException();
        }

        $this->clearRateLimitingAttempts();
        $user = User::where('email', $payload->user->email())->first();
        $tokenService = new TokenService($user);

        return new AuthnResult(
            bearer: $payload->tokens['access_token'],
            expiresIn: now('UTC')->addSeconds($payload->tokens['expires_in']),
            maxAge: $payload->tokens['expires_in'],
            refresh: $tokenService->getRefreshCookieToken($payload->tokens['refresh_token']),
            csrf: $tokenService->getCsrfCookieToken(),
            user: $user
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
