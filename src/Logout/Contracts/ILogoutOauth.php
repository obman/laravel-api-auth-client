<?php

namespace Obman\LaravelApiAuthClient\Logout\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;

interface ILogoutOauth
{
    public function destroyTokens(Authenticatable $user): AuthnResult;
}
