<?php

namespace Obman\LaravelApiAuthClient\Authn\Passport;

use Obman\LaravelApiAuthClient\Authn\BaseAuthn;
use Obman\LaravelApiAuthClient\DTO\AuthnPayload;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\Services\TokenService;
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
