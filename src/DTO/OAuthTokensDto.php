<?php

namespace Obman\LaravelApiAuthClient\DTO;

class OAuthTokensDto
{
    public function __construct(
        public readonly ?string $accessToken = null,
        public readonly ?string $refreshToken = null,
        public readonly ?int $expiresIn = null,
    )
    {}
}
