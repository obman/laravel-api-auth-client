<?php

namespace Obman\LaravelApiAuthClient\Authn\Sanctum;

use Obman\LaravelApiAuthClient\Authn\BaseAuthn;
use Obman\LaravelApiAuthClient\Exceptions\CredentialsMissingException;
use Obman\LaravelApiAuthClient\DTO\AuthnPayload;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\Services\TokenService;
use Illuminate\Auth\Events\Login;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Obman\LaravelApiAuthClient\Exceptions\UserMissingException;

class Basic extends BaseAuthn
{
    private function canProcced(AuthnPayload $payload): bool
    {
        if (empty($payload->user)) {
            throw new UserMissingException();
        }
        if (empty($payload->credentials)) {
            throw new CredentialsMissingException();
        }

        return true;
    }

    private function getAuthResult(AuthnPayload $payload, TokenService $tokenService, ?Authenticatable $user = null): AuthnResult
    {
        $expiration = (int) config('apiauthclient.token.access.expiration');
        return new AuthnResult(
            bearer: $tokenService->getAccessToken(),
            expiresIn: now('UTC')->addSeconds($expiration),
            maxAge: $expiration,
            refresh: $tokenService->getRefreshCookieToken($payload->tokens->refreshToken),
            csrf: $this->isCsrfEnabled() ? $tokenService->getCsrfCookieToken() : null,
            user: $user
        );
    }

    public function authenticate(AuthnPayload $payload): AuthnResult
    {
        $this->canProcced($payload);

        $passwdColumn = config('apiauthclient.password_identifier_column');
        $rememberColumn = config('rememberme.password_identifier_column');
        if (!$payload->user || ! Hash::check($payload->user->{$passwdColumn}, $payload->credentials->password)) {
            throw ValidationException::withMessages([
                'email' => __('auth.failed'),
            ]);
        }

        $this->clearRateLimitingAttempts();
        event(new Login(auth()->getDefaultDriver(), $payload->user, $payload->credentials->{$rememberColumn}));

        $tokenService = new TokenService($payload->user);
        return $this->getAuthResult($tokenService, $payload->user);
    }

    public function refresh(AuthnPayload $payload): AuthnResult
    {
        $this->canProcced($payload);

        $this->clearRateLimitingAttempts();
        // TODO: add event for refresh token
        $tokenService = new TokenService($payload->user);
        return $this->getAuthResult($tokenService);
    }
}
