<?php

namespace FlyDevLabs\ApiAuthClient\Generators;

use Illuminate\Contracts\Auth\Authenticatable;

class TokenGenerator
{
    public function generate(Authenticatable $user, string $name, \DateTime $expiration, array $abilities = []): string
    {
        $token = $user->createToken($name, $abilities, $expiration)->plainTextToken;
        $position = strpos($token, '|');
        return substr($token, $position + 1);
    }
}
