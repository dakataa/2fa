<?php

namespace Dakataa\Security\TwoFactorAuthenticator\EventHandler\Listener;


use Dakataa\Security\TwoFactorAuthenticator\Authentication\Token\TwoFactorAuthenticationToken;
use Dakataa\Security\TwoFactorAuthenticator\EventHandler\Event\TwoFactorActivateEvent;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticatorProvider;
use Exception;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Event\AuthenticationTokenCreatedEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Throwable;

final class TwoFactorAuthenticatorListener
{
    protected bool $enabled = false;

    public function __construct(
        private HttpUtils $httpUtils,
        private RouterInterface $router,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly TwoFactorAuthenticatorProvider $twoFactorProvider,
        private readonly ParameterBagInterface $parameterBag,
        private readonly UserProviderInterface $userProvider,
        private readonly Security $security

    ) {
        $this->enabled = $this->parameterBag->get('dakataa_two_factor_authenticator.enabled');
    }

    #[AsEventListener(event: AuthenticationTokenCreatedEvent::class)]
    public function onAuthenticationTokenCreatedEvent(AuthenticationTokenCreatedEvent $event): void
    {
        if (!$this->enabled) {
            return;
        }

        if (!$event->getPassport()->hasBadge(PasswordCredentials::class)) {
            return;
        }

        $parentToken = $event->getAuthenticatedToken();
        $token = new TwoFactorAuthenticationToken($parentToken->getUser());
        $event->setAuthenticatedToken($token);
    }

    #[AsEventListener(event: LoginSuccessEvent::class)]
    public function onLoginSuccessEvent(LoginSuccessEvent $event): void
    {
        if (!$this->enabled) {
            return;
        }

        $token = $event->getAuthenticatedToken();
        if (false === $token instanceof TwoFactorAuthenticationToken) {
            return;
        }

        $twoFactorAuthenticator = $this->twoFactorProvider->getAuthenticator($token->getUser());
        if (!$twoFactorAuthenticator) {
            return;
        }

        $twoFactorEntity = $this->twoFactorProvider->getEntity($token->getUser());
        if (!$twoFactorEntity->isTwoFactorActive()) {
            return;
        }

        if (!$twoFactorAuthenticator->isDispatched($twoFactorEntity)) {
            $twoFactorAuthenticator->dispatch($twoFactorEntity);
        }

        $request = $event->getRequest();
        $response = match ($request->getContentTypeFormat()) {
            'json' => new JsonResponse([
                'challenge' => [
                    'type' => $twoFactorEntity->getTwoFactorAuthenticator(),
                    'url' => $this->httpUtils->generateUri(
                        $request,
                        $this->parameterBag->get('dakataa_two_factor_authenticator.code.check')
                    ),
                    'required_fields' => [
                        ...(!$request->getSession()->isStarted() ? [
                            $this->parameterBag->get(
                                'dakataa_two_factor_authenticator.username_path'
                            ),
                        ] : []),
                        $this->parameterBag->get('dakataa_two_factor_authenticator.code.field_path'),
                    ],
                ],
            ]),
            default => (function () use ($request) {
                $codeForm = $this->parameterBag->get('dakataa_two_factor_authenticator.code.form');

                try {
                    if (!$this->router->getRouteCollection()->get($codeForm)) {
                        $this->router->match($codeForm);
                    }
                } catch (Throwable) {
                    throw new InvalidConfigurationException(sprintf('Missing route for 2FA code form: %s', $codeForm));
                }

                return $this->httpUtils->createRedirectResponse(
                    $request,
                    $this->httpUtils->generateUri($request, $codeForm)
                );
            })()
        };

        $event->setResponse($response);
    }

    #[AsEventListener(event: RequestEvent::class)]
    public function onRequestEvent(RequestEvent $event): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->codeCheckRequestHandler($event);
    }

    private function codeCheckRequestHandler(RequestEvent $event): void
    {
        $codeCheckRoute = $this->parameterBag->get('dakataa_two_factor_authenticator.code.check');
        if (!$this->httpUtils->checkRequestPath($event->getRequest(), $codeCheckRoute)) {
            return;
        }

        try {
            if (!$this->router->getRouteCollection()->get($codeCheckRoute)) {
                $this->router->match($codeCheckRoute);
            }
        } catch (Throwable) {
            throw new InvalidConfigurationException(sprintf('Missing route for 2FA code check: %s', $codeCheckRoute));
        }

        $request = $event->getRequest();

        $getAccessorPath = fn(string $path) => implode(
            '',
            array_map(fn(string $v) => sprintf('[%s]', $v),
                explode(
                    '.',
                    trim(
                        str_replace(
                            ['[', ']'],
                            ['', '.'],
                            $this->parameterBag->get($path)
                        ),
                        '.'
                    )
                )
            )
        );

        try {
            $codeAccessorPath = $getAccessorPath('dakataa_two_factor_authenticator.code.field_path');
            $usernameAccessorPath = $getAccessorPath('dakataa_two_factor_authenticator.username_path');

            $requestData = match ($request->getContentTypeFormat()) {
                'form' => $request->request->all(),
                'json' => $request->getPayload()->all(),
                default => array_merge(
                    $request->request->all(),
                    $request->getPayload()->all(),
                    $request->query->all()
                )
            };

            $propertyAccessor = PropertyAccess::createPropertyAccessorBuilder()
                ->disableExceptionOnInvalidPropertyPath()
                ->getPropertyAccessor();

            $username = $request->getSession()->isStarted() ? $request->getSession()->get(
                SecurityRequestAttributes::LAST_USERNAME
            ) : $propertyAccessor->getValue($requestData, $usernameAccessorPath);
            $code = $propertyAccessor->getValue($requestData, $codeAccessorPath);

            if (!$username) {
                throw new BadCredentialsException('Invalid Username.');
            }

            if (!$code) {
                throw new BadCredentialsException('Invalid Auth Code.');
            }

            $user = $this->userProvider->loadUserByIdentifier($username);
            $twoFactorAuthenticator = $this->twoFactorProvider->getAuthenticator($user);
            if (!$twoFactorAuthenticator) {
                throw new Exception('Two Factor Authenticator not configured for this user.');
            }

            $twoFactorEntity = $this->twoFactorProvider->getEntity($user);
            if (!$twoFactorAuthenticator->isDispatched($twoFactorEntity)) {
                throw new BadCredentialsException('Two Factor Authentication is not dispatched.');
            }

            if (!$twoFactorAuthenticator->validate(
                $twoFactorEntity,
                $code
            )) {
                throw new BadCredentialsException(
                    'Invalid Two Factor Credentials.'
                );
            }

            if ($twoFactorEntity->isTwoFactorActive()) {
                $event->setResponse($this->security->login($user));
            } else {
                $this->eventDispatcher->dispatch(new TwoFactorActivateEvent($user, $twoFactorEntity));
            }
        } catch (Throwable $e) {
            $event->setResponse(new JsonResponse([
                'message' => 'Invalid Credentials',
                'originalMessage' => $e->getMessage(),
                'requirements' => [
                    'twoFactorAuthenticator' => [
                        'fields' => [
                            ...(!$request->getSession()->isStarted() ? [
                                $this->parameterBag->get(
                                    'dakataa_two_factor_authenticator.username_path'
                                ),
                            ] : []),
                            $this->parameterBag->get('dakataa_two_factor_authenticator.code.field_path'),
                        ],
                    ],
                ],
            ], 400));
        }

    }
}
