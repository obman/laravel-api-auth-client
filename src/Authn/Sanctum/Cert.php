<?php

namespace Obman\LaravelApiAuthClient\Authn\Sanctum;

use Obman\LaravelApiAuthClient\Authn\BaseAuthn;
use App\Models\User;

class Cert extends BaseAuthn
{

    public function authenticate(): mixed
    {
        $user = User::where('email', $this->authUserDto->email)->firstOrFail();
        dd($user);
    }
}
