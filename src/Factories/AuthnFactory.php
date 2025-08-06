<?php

namespace Obman\LaravelApiAuthClient\Factories;

use Obman\LaravelApiAuthClient\DTO\AuthUserDto;
use Obman\LaravelApiAuthClient\Authn\IAuthn;
use Obman\LaravelApiAuthClient\Authn\JWT\Basic as JwtBasic;
use Obman\LaravelApiAuthClient\Authn\Passport\Basic as PassportBasic;
use Obman\LaravelApiAuthClient\Authn\Sanctum\Basic as SanctumBasic;
use Obman\LaravelApiAuthClient\Authn\Sanctum\Cert;
use Obman\LaravelApiAuthClient\Authn\Sanctum\TwoFA;
use Obman\LaravelApiAuthClient\Enums\AuthnType;
use Obman\LaravelApiAuthClient\Enums\ClientType;

class AuthnFactory
{
    private static function tryDetectingType()
    {
        if (class_exists(\Laravel\Sanctum\Sanctum::class)) {
            return ClientType::SANCTUM;
        }

        if (class_exists(\Laravel\Passport\Passport::class)) {
            return ClientType::PASSPORT;
        }

        if (class_exists(\Tymon\JWTAuth\JWT::class)) {
            return ClientType::JWT;
        }

        return null;
    }

    public static function make(AuthnType $type, AuthUserDto $authUserDto, ?ClientType $clientType = null): IAuthn
    {
        $clientType ??= self::tryDetectingType();

        if (! $clientType) {
            throw new \RuntimeException('No supported authentication client detected.');
        }

        return match ($clientType) {
            ClientType::JWT => match ($type) {
                AuthnType::BASIC => new JwtBasic($authUserDto),
            },
            ClientType::SANCTUM => match ($type) {
                AuthnType::BASIC => new SanctumBasic($authUserDto),
                AuthnType::TWO_FACTOR => new TwoFA($authUserDto),
                AuthnType::CERTIFICATE => new Cert($authUserDto)
            },
            ClientType::PASSPORT => match ($type) {
                AuthnType::BASIC => new PassportBasic($authUserDto)
            },
        };
    }
}
