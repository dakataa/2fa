<?php

namespace Dakataa\Security\TwoFactorAuthenticator\Authenticator;


use Dakataa\Security\TwoFactorAuthenticator\Notification\EmailNotification;
use Dakataa\Security\TwoFactorAuthenticator\Notification\NotificationInterface;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;

class EmailAuthenticator extends AbstractAuthenticator
{
    public function createNotification(TwoFactorAuthenticatorEntityInterface $entity, string $code): NotificationInterface
    {
        return new EMailNotification($entity, $code);
    }
}
