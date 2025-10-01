<?php

namespace Obman\LaravelApiAuthClient\Logout\Passport;

use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Token;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\Logout\BaseLogout;
use Obman\LaravelApiAuthClient\Logout\Contracts\ILogoutOauth;
use Obman\LaravelApiAuthClient\Services\TokenService;

class Basic extends BaseLogout implements ILogoutOauth
{
    public function destroyTokens(Authenticatable $user): AuthnResult
    {
        $tokenService = new TokenService($user);
        $user->tokens()
            ->where('revoked', false)
            ->each(function (Token $token) {
                $token->revoke();
                $token->refreshToken?->revoke();
            });

        return new AuthnResult(
            bearer: '',
            expiresIn: null,
            maxAge: 0,
            refresh: $tokenService->getEmptyRefreshToken(),
            csrf: $this->isCsrfEnabled() ? $tokenService->getCsrfCookieToken() : null
        );
    }
}
