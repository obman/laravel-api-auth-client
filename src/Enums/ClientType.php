<?php

namespace Obman\LaravelApiAuthClient\Enums;

enum ClientType: string
{
    case JWT = 'jwt';
    case SANCTUM = 'sanctum';
    case PASSPORT = 'passport';
}
