<?php

namespace Obman\LaravelApiAuthClient\Logout;

abstract class BaseLogout
{
    private array $config;

    public function __construct()
    {
        $this->config = config('apiauthclient');
    }

    protected function isCsrfEnabled(): bool
    {
        return $this->config['token']['csrf']['enable'];
    }
}
