<?php

namespace Obman\LaravelApiAuthClient;

use Laravel\Sanctum\PersonalAccessToken;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Obman\LaravelApiAuthClient\Middlewares\LoginThrottle;
use Obman\LaravelApiAuthClient\Middlewares\VerifyCookieTokens;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Obman\LaravelApiAuthClient\Enums\AuthnType;
use Obman\LaravelApiAuthClient\Enums\ClientType;
use Obman\LaravelApiAuthClient\Factories\ApiAuthClientFactory;

class ApiAuthClientServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/apiauthclient.php', 'apiauthclient');

        $this->app->singleton(ApiAuthClientFactory::class);
        $this->app->singleton(ApiAuthClient::class, function () {
            $authnType = AuthnType::tryFrom(config('apiauthclient.default_authn_type')) ?? AuthnType::BASIC;
            $clientType = ClientType::tryFrom(config('apiauthclient.default_client_type')) ?? ClientType::PASSPORT;

            return new ApiAuthClient($authnType, $clientType);
        });
    }

    /**
     * @throws BindingResolutionException
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/apiauthclient.php' => config_path('/apiauthclient.php'),
        ], 'apiauthclient-config');

        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('apiauthclient.login.throttle', LoginThrottle::class);
        $router->aliasMiddleware('apiauthclient.verify.tokens', VerifyCookieTokens::class);

        /**
         * Custom auth guard for refresh tokens
         */
        Auth::viaRequest('sanctum-refresh-token', function (Request $request): Authenticatable|null {
            $headerXSRF = $request->header('X-XSRF-TOKEN');
            $cookieXSRF = $request->cookie('XSRF-TOKEN');

            if (!$headerXSRF || !$cookieXSRF || $headerXSRF !== $cookieXSRF) {
                return null;
            }

            $refreshToken = $request->cookie(config('sanctum.rt_token_label'));
            if (!$refreshToken) {
                return null;
            }

            $token = PersonalAccessToken::where('token', hash('sha256', $refreshToken))
                ->where('expires_at', '>', now())
                //->where('abilities', 'LIKE', '%' . TokenType::REFRESH_TOKEN->value . '%')
                ->first();
            if (!$token) {
                return null;
            }

            $user = $token->tokenable;
            if (!$user) {
                return null;
            }
            return $user;
        });
    }
}
