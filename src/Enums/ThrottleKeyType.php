<?php

namespace FlyDevLabs\ApiAuthClient\Enums;

enum ThrottleKeyType: string
{
    case USERNAME = 'username';
    case EMAIL = 'email';
}
