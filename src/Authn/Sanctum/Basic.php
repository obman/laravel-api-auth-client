<?php

namespace Obman\LaravelApiAuthClient\Authn\Sanctum;

use Obman\LaravelApiAuthClient\Authn\BaseAuthn;
use Obman\LaravelApiAuthClient\Exceptions\CredentialsMissingException;
use Obman\LaravelApiAuthClient\DTO\AuthnPayload;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\Services\TokenService;
use App\Models\User;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class Basic extends BaseAuthn
{
    public function authenticate(AuthnPayload $payload): AuthnResult
    {
        if (empty($payload->user)) {
            throw new CredentialsMissingException();
        }

        $user = User::where('email', $payload->user->email())->first();
        if (!$user || ! Hash::check($payload->user->password(), $user->password)) {
            throw ValidationException::withMessages([
                'email' => __('auth.failed'),
            ]);
        }

        $this->clearRateLimitingAttempts();
        event(new Login(auth()->getDefaultDriver(), $user, $payload->user->rememberMe()));

        $tokenService = new TokenService($user);
        return new AuthnResult(
            bearer: $tokenService->getAccessToken(),
            expiresIn: now('UTC')->addSeconds(config('apiauthclient.token.access.expiration'))->timestamp,
            refresh: $tokenService->getRefreshCookieToken(),
            csrf: $tokenService->getCsrfCookieToken(),
            user: $user
        );
    }

    public function refresh(AuthnPayload $payload): AuthnResult
    {
        if (empty($payload->user)) {
            throw new CredentialsMissingException();
        }

        $this->clearRateLimitingAttempts();
        $user = User::where('email', $payload->user->email())->first();
        // TODO: add event for refresh token
        $tokenService = new TokenService($user);
        return new AuthnResult(
            bearer: $tokenService->getAccessToken(),
            expiresIn: now('UTC')->addSeconds(config('apiauthclient.token.access.expiration'))->timestamp,
            refresh: $tokenService->getRefreshCookieToken(),
            csrf: $tokenService->getCsrfCookieToken(),
            user: null
        );
    }
}
