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
        $credentials = [
            'email' => $this->authUserDto->email,
            'password' => $this->authUserDto->password
        ];
        $token = auth()->attempt($credentials);
        if (!$token) {
            throw ValidationException::withMessages([
                'login' => 'Login failed. Email or password are incorrect',
            ]);
        }

        $this->clearRateLimitingAttempts();

        $tokenService = null;
        if ($payload->returnUser) {
            $user = auth()->user();
            $tokenService = new TokenService($user);
            event(new Login(auth()->getDefaultDriver(), $user, $this->authUserDto->rememberMe));
        }

        return new AuthnResult(
            bearer: $token,
            expiresIn: now('UTC')->addSeconds(config('apiauthclient.token.access.expiration'))->timestamp,
            refresh: $tokenService?->getRefreshCookieToken(JWTAuth::fromUser($user)),
            csrf: $tokenService?->getCsrfCookieToken(),
            user: $payload->returnUser ? $user : null
        );
    }
}
