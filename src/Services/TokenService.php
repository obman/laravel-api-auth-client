<?php

namespace Obman\LaravelApiAuthClient\Services;

use Obman\LaravelApiAuthClient\DTO\TokenSettings;
use Obman\LaravelApiAuthClient\Enums\TokenType;
use Obman\LaravelApiAuthClient\Generators\CookieGenerator;
use Obman\LaravelApiAuthClient\Generators\TokenGenerator;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Cookie;

class TokenService
{
    private array $config;
    private TokenGenerator $tokenGenerator;
    private CookieGenerator $cookieGenerator;

    public function __construct(
        private ?Authenticatable $user
    )
    {
        $this->config = config('apiauthclient');
        $this->tokenGenerator = new TokenGenerator();
        $this->cookieGenerator = new CookieGenerator();
    }

    public function getAccessToken(): string
    {
        $accessTokenConf = $this->config['token']['access'];
        $name = $accessTokenConf['label'] . $this->user->email;
        $expiration = now()->addMinutes((int) $accessTokenConf['expiration']);
        $abilities = [TokenType::ACCESS_TOKEN];
        return $this->tokenGenerator->generate($this->user, $name, $expiration, $abilities);
    }

    public function getRefreshCookieToken(?string $token = null): Cookie
    {
        $refreshTokenConf = $this->config['token']['refresh'];
        $tokenSettings = new TokenSettings($refreshTokenConf['label'], $refreshTokenConf['expiration']);

        if ($token !== null) {
            $cookieToken = $token;
        } elseif ($this->user !== null) {
            $tokenName = $tokenSettings->label . $this->user->email;
            $tokenExpiration = now()->addMinutes($tokenSettings->expiration);
            $abilities = [TokenType::REFRESH_TOKEN];
            $cookieToken = $this->tokenGenerator->generate($this->user, $tokenName, $tokenExpiration, $abilities);
        } else {
            throw new \InvalidArgumentException('Either user or token must be provided to generate refresh cookie token.');
        }

        $cookieConf = $this->config['cookie'];
        return $this->cookieGenerator->generate(
            $tokenSettings->label,
            $cookieToken,
            $tokenSettings->expiration,
            $cookieConf['path'],
            $cookieConf['domain'],
            $cookieConf['production'],
            true
        );
    }

    public function getCsrfCookieToken(): Cookie
    {
        $csrfConfig = $this->config['token']['csrf'];
        $tokenSettings = new TokenSettings($csrfConfig['label'], $csrfConfig['expiration']);
        $token = hash('sha256', Str::random(40));
        $cookieConf = $this->config['cookie'];
        $path = $cookieConf['path'];
        $domain = $cookieConf['domain'];
        return $this->cookieGenerator->generate($tokenSettings->label, $token, $tokenSettings->expiration, $path, $domain, $cookieConf['production']);
    }

    public function getEmptyRefreshToken(): Cookie
    {
        $config = $this->config['token']['refresh'];
        $tokenSettings = new TokenSettings($config['label'], $config['expiration']);
        $cookieConf = $this->config['cookie'];
        return $this->cookieGenerator->generate($tokenSettings->label, '', -1, $cookieConf['path'], '', $cookieConf['production']);
    }
}
