<?php

namespace FlyDevLabs\ApiAuthClient\Generators;

use Symfony\Component\HttpFoundation\Cookie;

class CookieGenerator
{
    public function generate(string $name, string $token, int $expiration, string $path, string $domain, bool $isProduction): Cookie
    {
        return cookie(
            $name,
            $token,
            $expiration,
            $path,
            $domain,
            $isProduction,
            true,
            false,
            $isProduction ? 'strict' : 'lax'
        );
    }
}
