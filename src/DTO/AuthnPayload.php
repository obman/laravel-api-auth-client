<?php

namespace FlyDevLabs\ApiAuthClient\DTO;

readonly class AuthnPayload
{
    public function __construct(
        public bool  $returnUser = true,
        public array $tokens = []
    )
    {}
}
