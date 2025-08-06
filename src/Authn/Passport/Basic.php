<?php

namespace FlyDevLabs\ApiAuthClient\Authn\Passport;

use FlyDevLabs\ApiAuthClient\Authn\BaseAuthn;
use FlyDevLabs\ApiAuthClient\DTO\AuthnPayload;
use FlyDevLabs\ApiAuthClient\DTO\AuthnResult;
use FlyDevLabs\ApiAuthClient\Services\TokenService;
use App\Models\User;

class Basic extends BaseAuthn
{
    public function authenticate(AuthnPayload $payload): AuthnResult
    {
        $user = User::where('email', $this->authUserDto->email)->first();
        $this->clearRateLimitingAttempts();

        $tokenService = new TokenService($user);
        return new AuthnResult(
            bearer: $payload->tokens['access_token'],
            expiresIn: now('UTC')->addSeconds($payload->tokens['expires_in'])->timestamp,
            refresh: $tokenService->getRefreshCookieToken($payload->tokens['refresh_token']),
            csrf: $tokenService->getCsrfCookieToken(),
            user: $payload->returnUser ? $user : null
        );
    }
}
