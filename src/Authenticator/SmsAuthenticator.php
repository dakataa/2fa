<?php

namespace Dakataa\Security\TwoFactorAuthenticator\Authenticator;


use Dakataa\Security\TwoFactorAuthenticator\Notification\NotificationInterface;
use Dakataa\Security\TwoFactorAuthenticator\Notification\SmsNotification;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;

class SmsAuthenticator extends AbstractAuthenticator
{
    public function createNotification(
        TwoFactorAuthenticatorEntityInterface $entity,
        string $code
    ): NotificationInterface {
        return new SmsNotification($entity, $code);
    }
}
