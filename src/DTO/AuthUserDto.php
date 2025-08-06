<?php

namespace Obman\LaravelApiAuthClient\DTO;

readonly class AuthUserDto
{
    public function __construct(
        private array $params
    )
    {}

    public function get(string $key): mixed
    {
        return $this->params[$key] ?? null;
    }

    public function email(): ?string
    {
        return $this->params['email'] ?? null;
    }

    public function password(): ?string
    {
        return $this->params['password'] ?? null;
    }

    public function rememberMe(): bool
    {
        return $this->params['remember_me'] ?? false;
    }

    public function all(): array
    {
        return $this->params;
    }
}
