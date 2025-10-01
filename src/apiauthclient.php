<?php

return [
    'limiter_key_label' => env('API_AUTH_CLIENT_LIMITER_KEY', 'limiterKey'),
    'token' => [
        'access' => [
            'label' => env('API_AUTH_CLIENT_ACCESS_TOKEN_LABEL', 'access:token'),
            'expiration' => env('API_AUTH_CLIENT_ACCESS_TOKEN_EXPIRATION_MINUTES', 10)
        ],
        'refresh' => [
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
        'domain' => env('API_AUTH_CLIENT_COOKIE_DOMAIN', 'localhost'),
        'production' => env('API_AUTH_CLIENT_COOKIE_PRODUCTION', false)
    ]
];
