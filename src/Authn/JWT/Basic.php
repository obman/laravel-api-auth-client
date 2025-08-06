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
        $oldRefreshToken = $payload->tokens['refresh_token'];
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
            expiresIn: now('UTC')->addSeconds(config('apiauthclient.token.access.expiration'))->timestamp,
            refresh: $tokenService->getRefreshCookieToken($refreshToken),
            csrf: $tokenService->getCsrfCookieToken(),
            user: null
        );
    }
}
