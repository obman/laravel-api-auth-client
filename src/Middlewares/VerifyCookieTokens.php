<?php

namespace Obman\LaravelApiAuthClient\Middlewares;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;

class VerifyCookieTokens
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $headerXSRF = $request->header('X-XSRF-TOKEN');
        $cookieXSRF = $request->cookie('XSRF-TOKEN');

        if (!$headerXSRF || !$cookieXSRF || $headerXSRF !== $cookieXSRF) {
            $clearCookie = Cookie::forget(REFRESH_TOKEN_LABEL);
            return response(['message' => 'Invalid CSRF token'], 403)->withCookie($clearCookie);
        }

        $refreshToken = $request->cookie(REFRESH_TOKEN_LABEL);
        if (!$refreshToken) {
            return response(['message' => 'Missing refresh token'], 401);
        }

        return $next($request);
    }
}
