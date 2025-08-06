<?php

namespace Obman\LaravelApiAuthClient;

use Obman\LaravelApiAuthClient\DTO\AuthnPayload;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\DTO\AuthUserDto;
use Obman\LaravelApiAuthClient\Authn\IAuthn;
use Obman\LaravelApiAuthClient\Enums\AuthnType;
use Obman\LaravelApiAuthClient\Enums\ClientType;
use Obman\LaravelApiAuthClient\Factories\AuthnFactory;

class ApiAuthClient
{
    private IAuthn $authn;

    public function __construct(AuthnType $authnType, array $credentials, ?ClientType $clientType = null)
    {
        $dto = new AuthUserDto($credentials['email'], $credentials['password'], $credentials['remember_me'] ?? false);
        $this->authn = AuthnFactory::make($authnType, $dto, $clientType);
    }

    public function getAuthnPayload(array $tokens, bool $returnUser): AuthnPayload
    {
        return new AuthnPayload($returnUser, $tokens);
    }

    public function authenticate(array $tokens = [], bool $returnUser = true): AuthnResult
    {
        $payload = $this->getAuthnPayload($tokens, $returnUser);
        return $this->authn->authenticate($payload);
    }
}
