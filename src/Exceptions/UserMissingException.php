<?php

namespace Obman\LaravelApiAuthClient\Exceptions;

use Exception;

class UserMissingException extends Exception
{
    protected $message = 'User is missing or are incorrect.';
}
