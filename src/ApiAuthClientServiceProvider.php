<?php

namespace Obman\LaravelApiAuthClient;

use Obman\LaravelApiAuthClient\Middlewares\LoginThrottle;
use Obman\LaravelApiAuthClient\Middlewares\VerifyCookieTokens;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

class ApiAuthClientServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/apiauthclient.php', 'apiauthclient');
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
    }
}
