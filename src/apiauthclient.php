<?php

return [
    'default_authn_type' => env('API_AUTH_CLIENT_DEFAULT_AUTHN_TYPE'),
    'default_client_type' => env('API_AUTH_CLIENT_DEFAULT_CLIENT_TYPE'),

    'user_model' => env('API_AUTH_CLIENT_USER_MODEL', Illuminate\Contracts\Auth\Authenticatable::class),
    'email_identifier_column' => env('API_AUTH_CLIENT_EMAIL_IDENTIFIER_COLUMN', 'email'),
    'password_identifier_column' => env('API_AUTH_CLIENT_PASSWORD_IDENTIFIER_COLUMN', 'password'),
    'rememberme_identifier_column' => env('API_AUTH_CLIENT_REMEMBERME_IDENTIFIER_COLUMN', 'remember_me'),

    'limiter_key_label' => env('API_AUTH_CLIENT_LIMITER_KEY', 'limiterKey'),

    'token' => [
        'expiration_identifier' => env(' API_AUTH_CLIENT_ACCESS_TOKEN_EXPIRATION_IDENTIFIER ', 'expires_in'),
        'access' => [
            'identifier' => env('API_AUTH_CLIENT_ACCESS_TOKEN_IDENTIFIER', 'access_token'),
            'label' => env('API_AUTH_CLIENT_ACCESS_TOKEN_LABEL', 'access:token'),
            'expiration' => env('API_AUTH_CLIENT_ACCESS_TOKEN_EXPIRATION_MINUTES', 10)
        ],
        'refresh' => [
            'identifier' => env('API_AUTH_CLIENT_REFRESH_TOKEN_IDENTIFIER', 'refresh_token'),
            'label' => env('API_AUTH_CLIENT_REFRESH_TOKEN_LABEL', 'refresh:token'),
            'expiration' => env('API_AUTH_CLIENT_REFRESH_TOKEN_EXPIRATION_MINUTES', 10080)
        ],
        'csrf' => [
            'enable' => env('API_AUTH_CLIENT_CSRF_TOKEN_ENABLE', false),
            'label' => env('API_AUTH_CLIENT_CSRF_TOKEN_LABEL', 'XSRF-TOKEN'),
            'header_label' => env('API_AUTH_CLIENT_CSRF_HEADER_LABEL', 'X-XSRF-TOKEN'),
            'expiration' => env('API_AUTH_CLIENT_CSRF_TOKEN_EXPIRATION_MINUTES', 10080)
        ]
    ],

    'cookie' => [
        'path' => env('API_AUTH_CLIENT_COOKIE_PATH', '/'),
        'domain' => env('API_AUTH_CLIENT_COOKIE_DOMAIN', env('APP_DOMAIN', 'localhost')),
        'production' => env('API_AUTH_CLIENT_COOKIE_PRODUCTION', false)
    ]
];
