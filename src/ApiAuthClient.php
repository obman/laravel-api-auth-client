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

    public function __construct(AuthnType $authnType, ?ClientType $clientType = null)
    {
        $this->authn = AuthnFactory::make($authnType, $clientType);
    }

    protected function getAuthnPayload(array $tokens, array $credentials = []): AuthnPayload
    {
        $dto = !empty($credentials) ? new AuthUserDto($credentials) : null;
        return new AuthnPayload($tokens, $dto);
    }

    public function authenticate(array $tokens = [], array $credentials = []): AuthnResult
    {
        $payload = $this->getAuthnPayload($tokens, $credentials);
        return $this->authn->authenticate($payload);
    }

    public function refresh(array $tokens = [], array $credentials = []): AuthnResult
    {
        $payload = $this->getAuthnPayload($tokens, $credentials);
        return $this->authn->refresh($payload);
    }
}
