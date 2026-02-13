<?php

namespace Obman\LaravelApiAuthClient\Factories;

use Obman\LaravelApiAuthClient\ApiAuthClient;
use Obman\LaravelApiAuthClient\Enums\AuthnType;

class ApiAuthClientFactory
{
    public function basic(): ApiAuthClient
    {
        return new ApiAuthClient(AuthnType::BASIC);
    }

    public function twoFA(): ApiAuthClient
    {
        return new ApiAuthClient(AuthnType::TWO_FACTOR);
    }

    public function cert(): ApiAuthClient
    {
        return new ApiAuthClient(AuthnType::CERTIFICATE);
    }

    public function sipass(): ApiAuthClient
    {
        return new ApiAuthClient(AuthnType::SIPASS);
    }
}
