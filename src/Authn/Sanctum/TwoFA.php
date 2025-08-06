<?php

namespace FlyDevLabs\ApiAuthClient\Authn\Sanctum;

use FlyDevLabs\ApiAuthClient\Authn\BaseAuthn;
use FlyDevLabs\ApiAuthClient\DTO\AuthUserDto;
use App\Models\User;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use RobThree\Auth\Providers\Qr\BaconQrCodeProvider;
use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\TwoFactorAuthException;

class TwoFA extends BaseAuthn
{
    private TwoFactorAuth $auth;

    /**
     * @throws TwoFactorAuthException
     */
    public function __construct(AuthUserDto $authUserDto)
    {
        parent::__construct($authUserDto);
        $this->auth = new TwoFactorAuth(new BaconQrCodeProvider());
    }

    /**
     * @throws ValidationException
     */
    public function authenticate(array $tokens = []): mixed
    {
        $user = User::where('email', $this->authUserDto->email)->firstOrFail();
        if (!$user || !Hash::check($this->authUserDto->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => __('auth.failed'),
            ]);
        }

        $this->clearRateLimitingAttempts();
        event(new Login(auth()->getDefaultDriver(), $user, $this->authUserDto->rememberMe));

        return $user;
        /*$token = new TokenService($user);
        try {
            return [
                'access_token' => $token->getAccessToken(),
                'refresh_cookie' => $token->getRefreshCookieToken(),
                'csrf_cookie' => $token->getCsrfToken(),
                'totp_img' => $this->auth->getQRCodeImageAsDataUri($user->email, $user->twofa_secret)
            ];
        } catch (TwoFactorAuthException $e) {
            report($e);
            throw ValidationException::withMessages([
                '2fa' => 'Failed to generate QR code',
            ]);
        }*/
    }
}
