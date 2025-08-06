<?php

namespace Obman\LaravelApiAuthClient\Authn\JWT;

use Obman\LaravelApiAuthClient\Authn\BaseAuthn;
use Obman\LaravelApiAuthClient\DTO\AuthnPayload;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\Services\TokenService;
use Illuminate\Auth\Events\Login;
use Illuminate\Validation\ValidationException;
use Tymon\JWTAuth\Facades\JWTAuth;

class Basic extends BaseAuthn
{
    public function authenticate(AuthnPayload $payload): AuthnResult
    {
        $token = auth()->attempt([
            'email' => $payload->user->email(),
            'password' => $payload->user->password()
        ]);
        if (!$token) {
            throw ValidationException::withMessages([
                'login' => 'Login failed. Email or password are incorrect',
            ]);
        }

        $this->clearRateLimitingAttempts();

        $user = auth()->user();
        $tokenService = new TokenService($user);
        event(new Login(auth()->getDefaultDriver(), $user, $payload->user->rememberMe()));

        return new AuthnResult(
            bearer: $token,
            expiresIn: now('UTC')->addSeconds(config('apiauthclient.token.access.expiration'))->timestamp,
            refresh: $tokenService->getRefreshCookieToken(JWTAuth::fromUser($user)),
            csrf: $tokenService->getCsrfCookieToken(),
            user: $user
        );
    }

    public function refresh(AuthnPayload $payload): AuthnResult
    {
        // TODO
    }
}
