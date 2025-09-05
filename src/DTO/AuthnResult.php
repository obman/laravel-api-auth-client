<?php

namespace Obman\LaravelApiAuthClient\DTO;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Carbon;
use Symfony\Component\HttpFoundation\Cookie;

readonly class AuthnResult
{
    public function __construct(
        public string           $bearer,
        public ?Carbon          $expiresIn = null,
        public ?int             $maxAge = null,
        public ?Cookie          $refresh = null,
        public ?Cookie          $csrf = null,
        public ?Authenticatable $user = null
    ) {}
}
