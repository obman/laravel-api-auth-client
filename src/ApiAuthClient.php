<?php

namespace FlyDevLabs\ApiAuthClient;

use FlyDevLabs\ApiAuthClient\DTO\AuthnPayload;
use FlyDevLabs\ApiAuthClient\DTO\AuthnResult;
use FlyDevLabs\ApiAuthClient\DTO\AuthUserDto;
use FlyDevLabs\ApiAuthClient\Authn\IAuthn;
use FlyDevLabs\ApiAuthClient\Enums\AuthnType;
use FlyDevLabs\ApiAuthClient\Enums\ClientType;
use FlyDevLabs\ApiAuthClient\Factories\AuthnFactory;

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
