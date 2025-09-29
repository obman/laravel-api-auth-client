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

class Basic extends BaseAuthn
{
    private function getAuthResult(TokenService $tokenService, ?Authenticatable $user = null): AuthnResult
    {
        $expiration = (int) config('apiauthclient.token.access.expiration');
        return new AuthnResult(
            bearer: $tokenService->getAccessToken(),
            expiresIn: now('UTC')->addSeconds($expiration),
            maxAge: $expiration,
            refresh: $tokenService->getRefreshCookieToken($payload->tokens['refresh_token']),
            csrf: $this->isCsrfEnabled() ? $tokenService->getCsrfCookieToken() : null,
            user: $user
        );
    }

    public function authenticate(AuthnPayload $payload): AuthnResult
    {
        if (empty($payload->user)) {
            throw new CredentialsMissingException();
        }

        $user = Authenticatable::where('email', $payload->user->email())->first();
        if (!$user || ! Hash::check($payload->user->password(), $user->password)) {
            throw ValidationException::withMessages([
                'email' => __('auth.failed'),
            ]);
        }

        $this->clearRateLimitingAttempts();
        event(new Login(auth()->getDefaultDriver(), $user, $payload->user->rememberMe()));

        $tokenService = new TokenService($user);
        return $this->getAuthResult($tokenService, $user);
    }

    public function refresh(AuthnPayload $payload): AuthnResult
    {
        if (empty($payload->user)) {
            throw new CredentialsMissingException();
        }

        $this->clearRateLimitingAttempts();
        $user = Authenticatable::where('email', $payload->user->email())->first();
        // TODO: add event for refresh token
        $tokenService = new TokenService($user);
        return $this->getAuthResult($tokenService);
    }
}
