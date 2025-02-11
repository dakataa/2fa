<?php

namespace Dakataa\Security\TwoFactorAuthenticator\EventHandler\Listener;


use Dakataa\Security\TwoFactorAuthenticator\DakataaTwoFactorAuthenticatorBundle;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticatorProvider;
use Symfony\Bundle\SecurityBundle\Security\FirewallMap;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\FirewallMapInterface;

final class TwoFactorAuthenticatorListener
{
    public function __construct(
        private readonly TwoFactorAuthenticatorProvider $twoFactorProvider,
        private readonly ParameterBagInterface $parameterBag
    ) {

    }

    #[AsEventListener(event: LoginSuccessEvent::class)]
    public function onLoginSuccessEvent(LoginSuccessEvent $event): void
    {
        if(!$this->parameterBag->get('dakataa_two_factor_authenticator.enabled')) {
            return;
        }

        $user = $event->getUser();
        $request = $event->getRequest();


        $twoFactorAuthenticator = $this->twoFactorProvider->getAuthenticator($user);
        $twoFactorEntity = $this->twoFactorProvider->getEntity($user);
        if ($twoFactorAuthenticator) {
            try {
                if (!$twoFactorAuthenticator->supports($twoFactorEntity)) {
                    $this->twoFactorProvider->setupProvider($user);
                    throw new BadCredentialsException('Two Factor Authentication not supported.');
                }

                if ($twoFactorAuthenticator->isDispatched($twoFactorEntity) && $request->getPayload()->has('code')) {
                    if (!$twoFactorAuthenticator->validate($twoFactorEntity, $request->getPayload()->getString('code'))) {
                        throw new BadCredentialsException(
                            'Invalid Two Factor Credentials. Please provide a valid Auth code.'
                        );
                    }
                } else {
                    $twoFactorAuthenticator->dispatch($twoFactorEntity);

                    throw new BadCredentialsException('Two Factor Authentication required.');
                }
            } catch (BadCredentialsException $e) {
                $event->setResponse(new JsonResponse([
                    'error' => $e->getMessage(),
                    'requirements' => [
                        'twoFactorAuthenticator' => [
                            'authenticator' => $twoFactorEntity->getTwoFactorAuthenticator(),
                            'fields' => [
                                'code',
                            ],
                        ],
                    ],
                ]));
            }
        }
    }

}
