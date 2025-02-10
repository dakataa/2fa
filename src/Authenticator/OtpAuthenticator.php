<?php

namespace Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\Authenticator;


use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;
use Exception;
use OTPHP\TOTP;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class OtpAuthenticator implements TwoFactorAuthenticatorInterface {

    public function __construct(ParameterBagInterface $parameterBag)
    {

    }

    public function setup(UserInterface $user): ?array
    {
        $otp = TOTP::generate();
        $otp->setLabel('User');
        $otp->setIssuer('Dakataa');

        return [
            'provisioningUri' => $otp->getProvisioningUri(),
            'secret' => $otp->getSecret(),
        ];
    }

    public function validate(TwoFactorAuthenticatorEntityInterface $entity, int|string $code): bool
    {
        if(null === $secret = $entity->getTwoFactorParameters()['secret'] ?? null)
            throw new Exception('OPT is not setup.');

        $otp = TOTP::createFromSecret($secret);

        return $otp->verify($code);
    }

    public function dispatch(TwoFactorAuthenticatorEntityInterface $entity): void
    {

    }

    public function isDispatched(TwoFactorAuthenticatorEntityInterface $entity): bool
    {
        return $this->supports($entity);
    }

    public function getTTL(): int
    {
        return 30;
    }

    public function supports(TwoFactorAuthenticatorEntityInterface $entity): bool
    {
        return !empty($entity->getTwoFactorParameters()['secret']);
    }
}
