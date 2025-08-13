<?php

namespace Obman\LaravelApiAuthClient\Factories;

use Obman\LaravelApiAuthClient\Enums\ClientType;

abstract class BaseAuthFactory
{
    protected static function tryDetectingType(): ?ClientType
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
}
