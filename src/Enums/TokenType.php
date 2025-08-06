<?php

namespace FlyDevLabs\ApiAuthClient\Enums;

enum TokenType: string
{
    case ACCESS_TOKEN = 'access-token';
    case REFRESH_TOKEN = 'refresh-token';
    case CSRF_TOKEN = 'csrf-token';
}
