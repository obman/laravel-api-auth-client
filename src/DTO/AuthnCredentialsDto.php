<?php

namespace Obman\LaravelApiAuthClient\DTO;

class AuthnCredentialsDto
{
    public function __construct(
        public readonly string $email,
        public readonly string $password,
        public readonly bool $rememberMe = false,
    )
    {}
}
