<?php

namespace Obman\LaravelApiAuthClient\DTO;

readonly class AuthnPayload
{
    public function __construct(
        public array $tokens = [],
        public mixed $user = null
    )
    {}
}
