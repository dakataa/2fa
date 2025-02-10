<?php

namespace Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Notification;

use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;

readonly class EmailNotification
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
