<?php

namespace Obman\LaravelApiAuthClient\Enums;

enum ThrottleKeyType: string
{
    case USERNAME = 'username';
    case EMAIL = 'email';
}
