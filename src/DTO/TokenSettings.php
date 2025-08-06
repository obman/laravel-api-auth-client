<?php

namespace FlyDevLabs\ApiAuthClient\DTO;

readonly class TokenSettings
{
    public function __construct(
        public string $label,
        public int $expiration
    ) {}
}
