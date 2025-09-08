<?php

namespace Obman\LaravelApiAuthClient;

use Illuminate\Contracts\Auth\Authenticatable;
use Obman\LaravelApiAuthClient\Authn\IAuthn;
use Obman\LaravelApiAuthClient\DTO\AuthnPayload;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\DTO\AuthUserDto;
use Obman\LaravelApiAuthClient\Enums\AuthnType;
use Obman\LaravelApiAuthClient\Enums\ClientType;
use Obman\LaravelApiAuthClient\Factories\AuthnFactory;
use Obman\LaravelApiAuthClient\Factories\LogoutFactory;
use Obman\LaravelApiAuthClient\Logout\Contracts\ILogout;
use Obman\LaravelApiAuthClient\Logout\Contracts\ILogoutOauth;

class ApiAuthClient
{
    private IAuthn $authn;
    private ILogout|ILogoutOauth $logout;

    public function __construct(AuthnType $authnType, ?ClientType $clientType = null)
    {
        $this->authn = AuthnFactory::make($authnType, $clientType);
        $this->logout = LogoutFactory::make($authnType, $clientType);
    }

    protected function getAuthnPayload(array $tokens, ?array $credentials = [], mixed $user = null): AuthnPayload
    {
        if (!empty($credentials)) $dto = new AuthUserDto($credentials);
        elseif (!empty($user)) $dto = $user;
        else $dto = null;
        return new AuthnPayload($tokens, $dto);
    }

    public function authenticateWithCredentials(array $tokens = [], array $credentials = []): AuthnResult
    {
        $payload = $this->getAuthnPayload($tokens, credentials: $credentials);
        return $this->authn->authenticate($payload);
    }

    public function authenticateWithUser(array $tokens = [], mixed $user = null): AuthnResult
    {
        $payload = $this->getAuthnPayload($tokens, user: $user);
        return $this->authn->authenticate($payload);
    }

    public function refresh(array $tokens = [], array $credentials = []): AuthnResult
    {
        $payload = $this->getAuthnPayload($tokens, $credentials);
        return $this->authn->refresh($payload);
    }

    public function logout(?Authenticatable $user = null): AuthnResult
    {
        return $this->logout->destroyToken($user);
    }

    public function logoutOauth(Authenticatable $user): AuthnResult
    {
        return $this->logout->destroyTokens($user);
    }
}
