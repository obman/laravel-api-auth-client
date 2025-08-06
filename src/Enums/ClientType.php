<?php

namespace FlyDevLabs\ApiAuthClient\Enums;

enum ClientType: string
{
    case JWT = 'jwt';
    case SANCTUM = 'sanctum';
    case PASSPORT = 'passport';
}
