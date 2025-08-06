<?php

namespace Obman\LaravelApiAuthClient\DTO;

use Illuminate\Contracts\Auth\Authenticatable;
use Symfony\Component\HttpFoundation\Cookie;

readonly class AuthnResult
{
    public function __construct(
        public string           $bearer,
        public int              $expiresIn,
        public ?Cookie          $refresh = null,
        public ?Cookie          $csrf = null,
        public ?Authenticatable $user = null
    ) {}
}
