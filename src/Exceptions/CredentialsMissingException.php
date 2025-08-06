<?php

namespace Obman\LaravelApiAuthClient\Exceptions;

use Exception;

class CredentialsMissingException extends Exception
{
    protected $message = 'Credentials are missing or are incorrect.';
}
