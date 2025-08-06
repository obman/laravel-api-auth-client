<?php

namespace Obman\LaravelApiAuthClient\Middlewares;

use Obman\LaravelApiAuthClient\Enums\ThrottleKeyType;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Symfony\Component\HttpFoundation\Response;

class LoginThrottle
{
    public function handle(Request $request, Closure $next, $maxAttempts = 5, $decayMinutes = 1, string $throttleKey = ThrottleKeyType::USERNAME->value): Response
    {
        if ($throttleKey === ThrottleKeyType::USERNAME->value) {
            $key = strtolower((string) $request->username);
        }
        elseif ($throttleKey === ThrottleKeyType::EMAIL->value) {
            $key = strtolower((string) $request->email);
        }
        $ip = $request->ip();
        $limiterKey = 'login: ' . sha1("{$key}|{$ip}");

        if (RateLimiter::tooManyAttempts($limiterKey, $maxAttempts)) {
            return response()->json([
                'message' => 'Too many login attempts. Please try again later.',
                'retry_after_seconds' => RateLimiter::availableIn($limiterKey),
            ], 429);
            // TODO: add lockout event
        }

        RateLimiter::hit($limiterKey, $decayMinutes * 60);
        $request->attributes->set(config('apiauthclient.limiter_key_label'), $limiterKey);

        return $next($request);
    }
}
