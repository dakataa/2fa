<?php

namespace Dakataa\Security\TwoFactorAuthenticator\Notification;

use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;

abstract class AbstractNotification implements NotificationInterface
{
    public function __construct(
        private TwoFactorAuthenticatorEntityInterface $entity,
        private string $code
    ) {
    }

    public function getEntity(): TwoFactorAuthenticatorEntityInterface
    {
        return $this->entity;
    }

    public function getCode(): string
    {
        return $this->code;
    }


}
