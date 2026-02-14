<?php

namespace Obman\LaravelApiAuthClient\Generators;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;

class TokenGenerator
{
    public function generate(Authenticatable $user, string $name, Carbon $expiration, array $abilities = []): string
    {
        $token = $user->createToken($name, $abilities, $expiration)->plainTextToken;
        $position = strpos($token, '|');
        return substr($token, $position + 1);
    }
}
