<?php

namespace FlyDevLabs\ApiAuthClient\Authn;

use FlyDevLabs\ApiAuthClient\DTO\AuthnPayload;
use FlyDevLabs\ApiAuthClient\DTO\AuthnResult;
use Illuminate\Http\Request;

interface IAuthn
{
    public function authenticate(AuthnPayload $payload): AuthnResult;
}
