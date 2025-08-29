<?php

namespace Obman\LaravelApiAuthClient\Factories;

use Obman\LaravelApiAuthClient\Enums\AuthnType;
use Obman\LaravelApiAuthClient\Enums\ClientType;
use Obman\LaravelApiAuthClient\Logout\Contracts\ILogout;
use Obman\LaravelApiAuthClient\Logout\Contracts\ILogoutOauth;
use Obman\LaravelApiAuthClient\Logout\JWT\Basic as JwtBasic;
use Obman\LaravelApiAuthClient\Logout\Sanctum\Basic as SanctumBasic;
use Obman\LaravelApiAuthClient\Logout\Passport\Basic as PassportBasic;

class LogoutFactory extends BaseAuthFactory
{
    public static function make(AuthnType $type, ?ClientType $clientType = null): ILogout|ILogoutOauth
    {
        $clientType ??= self::tryDetectingType();

        if (! $clientType) {
            throw new \RuntimeException('No supported authentication client detected.');
        }

        return match ($clientType) {
            ClientType::JWT => match ($type) {
                AuthnType::BASIC => new JwtBasic(),
            },
            ClientType::SANCTUM => match ($type) {
                AuthnType::BASIC => new SanctumBasic(),
                //AuthnType::TWO_FACTOR => new TwoFA(),
                //AuthnType::CERTIFICATE => new Cert()
            },
            ClientType::PASSPORT => match ($type) {
                AuthnType::BASIC => new PassportBasic()
            },
        };
    }
}
