<?php

namespace FlyDevLabs\ApiAuthClient\Enums;

enum AuthnType: string
{
    case BASIC = 'basic';
    case TWO_FACTOR = '2fa';
    case CERTIFICATE = 'cert';
    case SIPASS = 'sipass';
}
