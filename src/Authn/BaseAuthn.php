<?php

namespace Obman\LaravelApiAuthClient\Authn;

use Obman\LaravelApiAuthClient\DTO\AuthnPayload;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\DTO\AuthUserDto;
use Illuminate\Support\Facades\RateLimiter;

abstract class BaseAuthn implements IAuthn
{
    private array $config;

    public function __construct()
    {
        $this->config = config('apiauthclient');
    }

    protected function isCsrfEnabled(): bool
    {
        return $this->config['token']['csrf']['enable'];
    }

    abstract public function authenticate(AuthnPayload $payload): AuthnResult;
    abstract public function refresh(AuthnPayload $payload): AuthnResult;

    public function clearRateLimitingAttempts(): void
    {
        $request = request();
        RateLimiter::clear($request->attributes->get(config('apiauthclient.limiter_key_label')));
    }
}
