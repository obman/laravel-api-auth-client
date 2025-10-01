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
        $authConf = config('apiauthclient.token');
        $csrfConf = $authConf['csrf'];
        $refreshTokenLabel = $authConf['refresh']['label'];
        if ($csrfConf['enable']) {
            $headerXSRF = $request->header($csrfConf['header_label']);
            $cookieXSRF = $request->cookie($csrfConf['label']);

            if (!$headerXSRF || !$cookieXSRF || $headerXSRF !== $cookieXSRF) {
                $clearCookie = Cookie::forget($refreshTokenLabel);
                return response(['code' => 'auth_failed_invalid_csrf_token'], 403)->withCookie($clearCookie);
            }
        }

        $refreshToken = $request->cookie($refreshTokenLabel);
        if (!$refreshToken) {
            return response(['code' => 'auth_failed_missing_refresh_token'], 401);
        }

        return $next($request);
    }
}
