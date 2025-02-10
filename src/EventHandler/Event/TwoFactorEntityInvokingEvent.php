<?php

namespace Dakataa\Security\TwoFactorAuthenticator\EventHandler\Event;

use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Contracts\EventDispatcher\Event;

class TwoFactorEntityInvokingEvent extends Event
{

    protected TwoFactorAuthenticatorEntityInterface|null $entity = null;

    public function __construct(private readonly UserInterface $user)
    {
    }

    public function getUser(): UserInterface {
        return $this->user;
    }
    public function setEntity(TwoFactorAuthenticatorEntityInterface $entity): static
    {
        $this->entity = $entity;

        return $this;
    }

    public function getEntity(): ?TwoFactorAuthenticatorEntityInterface
    {
        return $this->entity;
    }
}
