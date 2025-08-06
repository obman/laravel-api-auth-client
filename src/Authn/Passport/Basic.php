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
        $this->clearRateLimitingAttempts();
        if ($payload->returnUser) {
            $user = User::where('email', $this->authUserDto->email)->first();
            $tokenService = new TokenService($user);
        } else {
            $tokenService = new TokenService(null);
        }

        return new AuthnResult(
            bearer: $payload->tokens['access_token'],
            expiresIn: now('UTC')->addSeconds($payload->tokens['expires_in'])->timestamp,
            refresh: $tokenService?->getRefreshCookieToken($payload->tokens['refresh_token']),
            csrf: $tokenService?->getCsrfCookieToken(),
            user: $payload->returnUser ? $user : null
        );
    }
}
