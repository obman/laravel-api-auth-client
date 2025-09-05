<?php

namespace Obman\LaravelApiAuthClient\Generators;

use Symfony\Component\HttpFoundation\Cookie;

class CookieGenerator
{
    public function generate(string $name, string $token, int $expiration, string $path, string|bool $domain, bool $isProduction, bool $httpOnly = false): Cookie
    {
        return cookie(
            $name,
            $token,
            $expiration,
            $path,
            $domain,
            $isProduction,
            $httpOnly,
            false,
            $isProduction ? 'strict' : 'lax',
        );
    }
}
