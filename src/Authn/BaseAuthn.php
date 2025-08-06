<?php

namespace FlyDevLabs\ApiAuthClient\Authn;

use FlyDevLabs\ApiAuthClient\DTO\AuthnPayload;
use FlyDevLabs\ApiAuthClient\DTO\AuthnResult;
use FlyDevLabs\ApiAuthClient\DTO\AuthUserDto;
use Illuminate\Support\Facades\RateLimiter;

abstract class BaseAuthn implements IAuthn
{
    public function __construct(
        protected AuthUserDto $authUserDto
    )
    {}

    abstract public function authenticate(AuthnPayload $payload): AuthnResult;

    public function clearRateLimitingAttempts(): void
    {
        $request = request();
        RateLimiter::clear($request->attributes->get(config('apiauthclient.limiter_key_label')));
    }
}
