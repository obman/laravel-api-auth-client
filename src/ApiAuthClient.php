<?php

namespace Obman\LaravelApiAuthClient;

use Illuminate\Contracts\Auth\Authenticatable;
use Obman\LaravelApiAuthClient\Authn\IAuthn;
use Obman\LaravelApiAuthClient\DTO\AuthnCredentialsDto;
use Obman\LaravelApiAuthClient\DTO\AuthnPayload;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\DTO\OAuthTokensDto;
use Obman\LaravelApiAuthClient\Enums\AuthnType;
use Obman\LaravelApiAuthClient\Enums\ClientType;
use Obman\LaravelApiAuthClient\Exceptions\CredentialsMissingException;
use Obman\LaravelApiAuthClient\Exceptions\UserMissingException;
use Obman\LaravelApiAuthClient\Factories\AuthnFactory;
use Obman\LaravelApiAuthClient\Factories\LogoutFactory;
use Obman\LaravelApiAuthClient\Logout\Contracts\ILogout;
use Obman\LaravelApiAuthClient\Logout\Contracts\ILogoutOauth;

class ApiAuthClient
{
    private readonly array $config;
    private IAuthn $authn;
    private ILogout|ILogoutOauth $logout;

    public function __construct(AuthnType $authnType, ?ClientType $clientType = null)
    {
        $this->config = config('apiauthclient');
        $this->authn = AuthnFactory::make($authnType, $clientType);
        $this->logout = LogoutFactory::make($authnType, $clientType);
    }

    protected function resolveToModel(AuthnCredentialsDto $credentials): Authenticatable
    {
        $modelClass = $this->config['user_model'];
        return $modelClass::where($this->config['email_identifier_column'], $credentials->email)->firstOrFail();
    }

    protected function resolveToCredentialsDto(array $credentials): AuthnCredentialsDto
    {
        $emailColumn = $this->config['email_identifier_column'];
        $passwdColumn = $this->config['password_identifier_column'];
        if (empty($credentials[$emailColumn])) {
            throw new CredentialsMissingException('Email field missing in credentials.');
        }
        if (empty($credentials[$passwdColumn])) {
            throw new CredentialsMissingException('Password field missing in credentials.');
        }

        return new AuthnCredentialsDto(
            email: $credentials[$emailColumn],
            password: $credentials[$passwdColumn],
            rememberMe: !empty($credentials[$this->config['rememberme_identifier_column']]),
        );
    }

    protected function resolveToTokensDto(array $tokens): ?OAuthTokensDto
    {
        $tokenConfig = $this->config['token'];
        if (empty($tokens)) {
            return null;
        }

        return new OAuthTokensDto(
            accessToken: !empty($tokens[$tokenConfig['access']['identifier']]) ? $tokens[$tokenConfig['access']['identifier']] : null,
            refreshToken: !empty($tokens[$tokenConfig['refresh']['identifier']]) ? $tokens[$tokenConfig['refresh']['identifier']] : null,
            expiresIn: !empty($tokens[$tokenConfig['expiration_identifier']]) ? $tokens[$tokenConfig['expiration_identifier']] : null,
        );
    }

    protected function getAuthnPayload(array $tokens, ?array $credentials = [], ?Authenticatable $user = null): AuthnPayload
    {
        $authCredentials = null;
        if (!empty($credentials)) {
            $authCredentials = $this->resolveToCredentialsDto($credentials);
            $user = $this->resolveToModel($authCredentials);
        }
        elseif (!empty($user)) {
            if (!($user instanceof Authenticatable)) {
                throw new UserMissingException('Model does not implement Illuminate\Contracts\Auth\Authenticatable interface');
            }
        }

        $authTokens = $this->resolveToTokensDto($tokens);
        
        return new AuthnPayload($authTokens, $user, $authCredentials);
    }

    public function authenticateWithCredentials(array $tokens = [], array $credentials = []): AuthnResult
    {
        $payload = $this->getAuthnPayload($tokens, credentials: $credentials);
        return $this->authn->authenticate($payload);
    }

    public function authenticateWithUser(array $tokens = [], ?Authenticatable $user = null): AuthnResult
    {
        $payload = $this->getAuthnPayload($tokens, user: $user);
        return $this->authn->authenticate($payload);
    }

    public function refresh(array $tokens = [], array $credentials = []): AuthnResult
    {
        $payload = $this->getAuthnPayload($tokens, credentials: $credentials);
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
