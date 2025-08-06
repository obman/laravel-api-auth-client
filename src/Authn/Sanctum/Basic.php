<?php

namespace FlyDevLabs\ApiAuthClient\Authn\Sanctum;

use FlyDevLabs\ApiAuthClient\Authn\BaseAuthn;
use FlyDevLabs\ApiAuthClient\DTO\AuthnPayload;
use FlyDevLabs\ApiAuthClient\DTO\AuthnResult;
use FlyDevLabs\ApiAuthClient\Services\TokenService;
use App\Models\User;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class Basic extends BaseAuthn
{
    public function authenticate(AuthnPayload $payload): AuthnResult
    {
        $user = User::where('email', $this->authUserDto->email)->first();
        if (!$user || ! Hash::check($this->authUserDto->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => __('auth.failed'),
            ]);
        }

        $this->clearRateLimitingAttempts();
        event(new Login(auth()->getDefaultDriver(), $user, $this->authUserDto->rememberMe));

        $tokenService = new TokenService($user);
        return new AuthnResult(
            bearer: $tokenService->getAccessToken(),
            expiresIn: now('UTC')->addSeconds(config('apiauthclient.token.access.expiration'))->timestamp,
            refresh: $tokenService->getRefreshCookieToken(),
            csrf: $tokenService->getCsrfCookieToken(),
            user: $payload->returnUser ? $user : null
        );
    }
}
