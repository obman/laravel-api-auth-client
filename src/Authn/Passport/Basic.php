<?php

namespace Obman\LaravelApiAuthClient\Authn\Passport;

use Obman\LaravelApiAuthClient\Authn\BaseAuthn;
use Obman\LaravelApiAuthClient\DTO\AuthnPayload;
use Obman\LaravelApiAuthClient\DTO\AuthnResult;
use Obman\LaravelApiAuthClient\Exceptions\UserMissingException;
use Obman\LaravelApiAuthClient\Services\TokenService;

class Basic extends BaseAuthn
{
    private function getAuthResult(AuthnPayload $payload, TokenService $tokenService, bool $returnUser = false)
    {
        return new AuthnResult(
            bearer: $payload->tokens->accessToken,
            expiresIn: now('UTC')->addSeconds($payload->tokens->expiresIn),
            maxAge: $payload->tokens->expiresIn,
            refresh: $tokenService->getRefreshCookieToken($payload->tokens->refreshToken),
            csrf: $this->isCsrfEnabled() ? $tokenService->getCsrfCookieToken() : null,
            user: $returnUser ? $payload->user : null
        );
    }

    public function authenticate(AuthnPayload $payload): AuthnResult
    {
        if (empty($payload->user)) {
            throw new UserMissingException();
        }

        $this->clearRateLimitingAttempts();
        $tokenService = new TokenService($payload->user);

        return $this->getAuthResult($payload, $tokenService);
    }

    public function refresh(AuthnPayload $payload): AuthnResult
    {
        $this->clearRateLimitingAttempts();
        $tokenService = new TokenService(null);

        return $this->getAuthResult($payload, $tokenService);
    }
}
