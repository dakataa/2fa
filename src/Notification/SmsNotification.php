<?php

namespace Dakataa\Security\TwoFactorAuthenticator\Notification;

use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;

readonly class SmsNotification
{
    public function __construct(
        private TwoFactorAuthenticatorEntityInterface $user,
        private string $code
    ) {
    }

    public function getUser(): TwoFactorAuthenticatorEntityInterface
    {
        return $this->user;
    }

    public function getCode(): string
    {
        return $this->code;
    }


}
