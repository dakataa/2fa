<?php

namespace Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\EventHandler\Event;

use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Contracts\EventDispatcher\Event;

class TwoFactorSetupEvent extends Event
{

    private bool $isProcessed = false;

    public function __construct(private readonly UserInterface $user, private readonly TwoFactorAuthenticatorEntityInterface $entity)
    {
    }

    public function getEntity(): TwoFactorAuthenticatorEntityInterface {
        return $this->entity;
    }

    public function getUser(): UserInterface {
        return $this->user;
    }

    public function isProcessed(): bool
    {
        return $this->isProcessed;
    }

    public function setIsProcessed(bool $isProcessed): void
    {
        $this->isProcessed = $isProcessed;
    }

}
