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
        private Authenticatable $user
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
        $settings = new TokenSettings($refreshTokenConf['label'], $refreshTokenConf['expiration']);
        $tokenName = $settings->label . $this->user->email;
        $tokenExpiration = now()->addMinutes($settings->expiration);
        $abilities = [TokenType::REFRESH_TOKEN];
        if (!empty($token)) {
            $cookieToken = $token;
        } else {
            $cookieToken = $this->tokenGenerator->generate($this->user, $tokenName, $tokenExpiration, $abilities);
        }
        $cookieConf = $this->config['cookie'];
        $path = $cookieConf['path'];
        $domain = $cookieConf['domain'];
        return $this->cookieGenerator->generate($settings->label, $cookieToken, $settings->expiration, $path, $domain, false);
    }

    public function getCsrfCookieToken(): Cookie
    {
        $csrfConfig = $this->config['token']['csrf'];
        $name = $csrfConfig['label'];
        $expiration = $csrfConfig['expiration'];
        $token = hash('sha256', Str::random(40));
        $cookieConf = $this->config['cookie'];
        $path = $cookieConf['path'];
        $domain = $cookieConf['domain'];
        return $this->cookieGenerator->generate($name, $token, $expiration, $path, $domain, false);
    }
}
