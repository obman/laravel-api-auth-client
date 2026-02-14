<?php

namespace Obman\LaravelApiAuthClient\DTO;

use Illuminate\Contracts\Auth\Authenticatable;

readonly class AuthnPayload
{
    public function __construct(
        public readonly ?OAuthTokensDto $tokens = null,
        public readonly ?Authenticatable $user = null,
        public readonly ?AuthnCredentialsDto $credentials = null,
    )
    {}
}
