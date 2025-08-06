<?php

namespace Obman\LaravelApiAuthClient\DTO;

readonly class TokenSettings
{
    public function __construct(
        public string $label,
        public int $expiration
    ) {}
}
