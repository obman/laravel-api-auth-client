<?php

namespace Obman\LaravelApiAuthClient\Factories;

use Obman\LaravelApiAuthClient\Authn\IAuthn;
use Obman\LaravelApiAuthClient\Authn\JWT\Basic as JwtBasic;
use Obman\LaravelApiAuthClient\Authn\Passport\Basic as PassportBasic;
use Obman\LaravelApiAuthClient\Authn\Sanctum\Basic as SanctumBasic;
use Obman\LaravelApiAuthClient\Authn\Sanctum\Cert;
use Obman\LaravelApiAuthClient\Authn\Sanctum\TwoFA;
use Obman\LaravelApiAuthClient\Enums\AuthnType;
use Obman\LaravelApiAuthClient\Enums\ClientType;

class AuthnFactory extends BaseAuthFactory
{
    public static function make(AuthnType $authnType, ?ClientType $clientType = null): IAuthn
    {
        $clientType ??= self::tryDetectingType();

        if (! $clientType) {
            throw new \RuntimeException('No supported authentication client detected.');
        }

        return match ($clientType) {
            ClientType::JWT => match ($authnType) {
                AuthnType::BASIC => new JwtBasic(),
            },
            ClientType::SANCTUM => match ($authnType) {
                AuthnType::BASIC => new SanctumBasic(),
                AuthnType::TWO_FACTOR => new TwoFA(),
                AuthnType::CERTIFICATE => new Cert()
            },
            ClientType::PASSPORT => match ($authnType) {
                AuthnType::BASIC => new PassportBasic()
            },
        };
    }
}
