<?php

namespace Obman\LaravelApiAuthClient\Logout\Sanctum;

use Illuminate\Contracts\Auth\Authenticatable;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\Logout\BaseLogout;
use Obman\LaravelApiAuthClient\Logout\Contracts\ILogout;
use Obman\LaravelApiAuthClient\Logout\Contracts\ILogoutOauth;
use Obman\LaravelApiAuthClient\Services\TokenService;

class Basic extends BaseLogout implements ILogout, ILogoutOauth
{
    private array $config;

    public function __construct() {
        $this->config = config('apiauthclient.token');
    }

    public function destroyToken(?Authenticatable $user): AuthnResult
    {
        if (!$user) {
            throw new \Exception('Missing user.');
        }

        $user->currentAccessToken()->delete();
        $tokenService = new TokenService($user);
        return new AuthnResult(
            bearer: '',
            expiresIn: null,
            refresh: $tokenService->getEmptyRefreshToken(),
            csrf: $this->isCsrfEnabled() ? $tokenService->getCsrfCookieToken() : null
        );
    }

    public function destroyTokens(Authenticatable $user): AuthnResult
    {
        $atName = $this->config['access']['label'] . $user->email;
        $rtName = $this->config['refresh']['label'] . $user->email;
        $tokenService = new TokenService($user);
        $user->tokens()
            ->where('name', $atName)
            ->orWhere('name', $rtName)
            ->delete();

        return new AuthnResult(
            bearer: '',
            expiresIn: null,
            refresh: $tokenService->getEmptyRefreshToken(),
            csrf: $this->isCsrfEnabled() ? $tokenService->getCsrfCookieToken() : null
        );
    }
}
