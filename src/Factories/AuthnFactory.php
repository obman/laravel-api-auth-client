<?php

namespace FlyDevLabs\ApiAuthClient\Factories;

use FlyDevLabs\ApiAuthClient\DTO\AuthUserDto;
use FlyDevLabs\ApiAuthClient\Authn\IAuthn;
use FlyDevLabs\ApiAuthClient\Authn\JWT\Basic as JwtBasic;
use FlyDevLabs\ApiAuthClient\Authn\Passport\Basic as PassportBasic;
use FlyDevLabs\ApiAuthClient\Authn\Sanctum\Basic as SanctumBasic;
use FlyDevLabs\ApiAuthClient\Authn\Sanctum\Cert;
use FlyDevLabs\ApiAuthClient\Authn\Sanctum\TwoFA;
use FlyDevLabs\ApiAuthClient\Enums\AuthnType;
use FlyDevLabs\ApiAuthClient\Enums\ClientType;

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
