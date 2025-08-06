<?php

namespace FlyDevLabs\ApiAuthClient\Authn\Sanctum;

use FlyDevLabs\ApiAuthClient\Authn\BaseAuthn;
use App\Models\User;

class Cert extends BaseAuthn
{

    public function authenticate(): mixed
    {
        $user = User::where('email', $this->authUserDto->email)->firstOrFail();
        dd($user);
    }
}
