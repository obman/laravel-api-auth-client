<?php

return [
    'limiter_key_label' => env('API_AUTH_CLIENT_LIMITER_KEY', 'limiterKey'),
    'token' => [
        'access' => [
            'label' => env('API_AUTH_CLIENT_ACCESS_TOKEN_LABEL', 'access_token_'),
            'expiration' => env('API_AUTH_CLIENT_ACCESS_TOKEN_EXPIRATION', 10)
        ],
        'refresh' => [
            'label' => env('API_AUTH_CLIENT_REFRESH_TOKEN_LABEL', 'refresh_token_'),
            'expiration' => env('API_AUTH_CLIENT_REFRESH_TOKEN_EXPIRATION', 10080)
        ],
        'csrf' => [
            'label' => env('API_AUTH_CLIENT_CSRF_TOKEN_LABEL', 'XSRF-TOKEN'),
            'expiration' => env('API_AUTH_CLIENT_CSRF_TOKEN_EXPIRATION', 10080)
        ]
    ],
    'cookie' => [
        'path' => env('API_AUTH_CLIENT_COOKIE_PATH', '/'),
        'domain' => env('API_AUTH_CLIENT_COOKIE_DOMAIN', 'localhost')
    ]
];
