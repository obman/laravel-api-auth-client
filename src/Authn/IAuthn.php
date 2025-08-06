<?php

namespace Obman\LaravelApiAuthClient\Authn;

use Obman\LaravelApiAuthClient\DTO\AuthnPayload;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Illuminate\Http\Request;

interface IAuthn
{
    public function authenticate(AuthnPayload $payload): AuthnResult;
    public function refresh(AuthnPayload $payload): AuthnResult;
}
