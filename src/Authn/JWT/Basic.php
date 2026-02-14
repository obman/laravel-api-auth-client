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
        $emailColumn = config('apiauthclient.email_identifier_column');
        $passwdColumn = config('apiauthclient.password_identifier_column');
        $rememberColumn = config('rememberme.password_identifier_column');
        $token = auth()->attempt([
            'email' => $payload->user->{$emailColumn},
            'password' => $payload->user->{$passwdColumn}
        ]);
        if (!$token) {
            throw ValidationException::withMessages([
                'login' => 'Login failed. Email or password are incorrect',
            ]);
        }

        $this->clearRateLimitingAttempts();

        $user = auth()->user();
        $tokenService = new TokenService($user);
        event(new Login(auth()->getDefaultDriver(), $user, $payload->user->{$rememberColumn}));

        return new AuthnResult(
            bearer: $token,
            expiresIn: now('UTC')->addSeconds(config('apiauthclient.token.access.expiration')),
            refresh: $tokenService->getRefreshCookieToken(JWTAuth::fromUser($user)),
            csrf: $this->isCsrfEnabled() ? $tokenService->getCsrfCookieToken() : null,
            user: $user
        );
    }

    /**
     * Old/Expired token must be included in $payload
     * in order to generate new token.
     * When using api-auth-client refresh method passing
     * tokens array include token in this format: refresh_token => $value
     *
     * @param AuthnPayload $payload
     * @return AuthnResult
     * @throws \Exception
     */
    public function refresh(AuthnPayload $payload): AuthnResult
    {
        $oldRefreshToken = $payload->tokens->refreshToken;
        $tokenPayload = JWTAuth::setToken($oldRefreshToken)->getPayload();
        if ($tokenPayload->get('type') !== 'refresh') {
            throw new \Exception('Invalid token type');
        }

        $user = JWTAuth::setToken($oldRefreshToken)->toUser();
        if (!$user) {
            throw new \Exception('Username not found.');
        }

        $token = JWTAuth::fromUser($user); // bearer
        $refreshToken = JWTAuth::customClaims(['type' => 'refresh'])->fromUser($user);
        $tokenService = new TokenService($user);
        JWTAuth::setToken($oldRefreshToken)->invalidate();
        return new AuthnResult(
            bearer: $token,
            expiresIn: now('UTC')->addSeconds(config('apiauthclient.token.access.expiration')),
            refresh: $tokenService->getRefreshCookieToken($refreshToken),
            csrf: $this->isCsrfEnabled() ? $tokenService->getCsrfCookieToken() : null,
            user: null
        );
    }
}
