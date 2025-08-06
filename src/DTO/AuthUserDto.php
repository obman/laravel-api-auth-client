<?php

namespace Obman\LaravelApiAuthClient\DTO;

readonly class AuthUserDto
{
    public function __construct(
        public string $email,
        public ?string $password,
        public bool $rememberMe
    )
    {}
}
