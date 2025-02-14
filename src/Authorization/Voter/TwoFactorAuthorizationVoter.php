<?php

namespace Dakataa\Security\TwoFactorAuthenticator\Authorization\Voter;


use Dakataa\Security\TwoFactorAuthenticator\Authentication\Token\TwoFactorAuthenticationToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\CacheableVoterInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

final class TwoFactorAuthorizationVoter implements CacheableVoterInterface
{

    public function vote(TokenInterface $token, mixed $subject, array $attributes): int
    {
        if ($token instanceof TwoFactorAuthenticationToken) {
            return VoterInterface::ACCESS_DENIED;
        }

        return VoterInterface::ACCESS_ABSTAIN;
    }

    public function supportsAttribute(string $attribute): bool
    {
        return true;
    }

    public function supportsType(string $subjectType): bool
    {
        return true;
    }
}
