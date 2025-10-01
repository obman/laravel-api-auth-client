<?php

namespace Obman\LaravelApiAuthClient\Logout\JWT;

use Illuminate\Contracts\Auth\Authenticatable;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\Logout\BaseLogout;
use Obman\LaravelApiAuthClient\Logout\Contracts\ILogout;
use Obman\LaravelApiAuthClient\Services\TokenService;

class Basic extends BaseLogout implements ILogout
{
    public function destroyToken(?Authenticatable $user): AuthnResult
    {
        auth()->logout();
        $tokenService = new TokenService($user);
        return new AuthnResult(
            bearer: '',
            expiresIn: null,
            refresh: $tokenService->getEmptyRefreshToken(),
            csrf: $this->isCsrfEnabled() ? $tokenService->getCsrfCookieToken() : null
        );
    }
}
