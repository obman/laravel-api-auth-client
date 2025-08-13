<?php

namespace Obman\LaravelApiAuthClient\Logout\JWT;

use Illuminate\Contracts\Auth\Authenticatable;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\DTO\AuthUserDto;
use Obman\LaravelApiAuthClient\Logout\Contracts\ILogout;
use Obman\LaravelApiAuthClient\Services\TokenService;

class Basic implements ILogout
{
    public function destroyToken(?Authenticatable $user): AuthnResult
    {
        auth()->logout();
        $tokenService = new TokenService($user);
        return new AuthnResult(
            bearer: '',
            expiresIn: 0,
            refresh: $tokenService->getEmptyRefreshToken(),
            csrf: $tokenService->getCsrfCookieToken()
        );
    }
}
