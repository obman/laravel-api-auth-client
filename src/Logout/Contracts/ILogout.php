<?php

namespace Obman\LaravelApiAuthClient\Logout\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;

interface ILogout
{
    public function destroyToken(?Authenticatable $user): AuthnResult;
}
