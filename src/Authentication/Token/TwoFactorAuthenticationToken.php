<?php

namespace Dakataa\Security\TwoFactorAuthenticator\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;

class TwoFactorAuthenticationToken implements TokenInterface {

    public function __construct(public UserInterface $user)
    {

    }

    public function __toString(): string
    {
       return $this->getUserIdentifier();
    }

    public function getUserIdentifier(): string
    {
       return $this->getUser()?->getUserIdentifier() ?? '';
    }

    public function getRoleNames(): array
    {
        return [];
    }

    public function getUser(): ?UserInterface
    {
       return $this->user;
    }

    public function setUser(UserInterface $user): void
    {
        $this->user = $user;
    }

    public function eraseCredentials(): void
    {
    }

    public function getAttributes(): array
    {
        // TODO: Implement getAttributes() method.
    }

    public function setAttributes(array $attributes): void
    {
        // TODO: Implement setAttributes() method.
    }

    public function hasAttribute(string $name): bool
    {
        // TODO: Implement hasAttribute() method.
    }

    public function getAttribute(string $name): mixed
    {
    }

    public function setAttribute(string $name, mixed $value): void
    {
    }

    public function __serialize(): array
    {
        return [$this->user];
    }

    /**
     * Restores the object state from an array given by __serialize().
     *
     * There is no need to unserialize any entry in $data, they are already ready-to-use.
     * If you extend this method, keep in mind you MUST pass the parent data to its respective class.
     * Here is an example of how to extend this method:
     * <code>
     *     public function __unserialize(array $data): void
     *     {
     *         [$this->childAttribute, $parentData] = $data;
     *         parent::__unserialize($parentData);
     *     }
     * </code>
     *
     * @see __serialize()
     */
    public function __unserialize(array $data): void
    {
        [$user] = $data;
        $this->user = \is_string($user) ? new InMemoryUser($user, '', [], false) : $user;
    }
}
