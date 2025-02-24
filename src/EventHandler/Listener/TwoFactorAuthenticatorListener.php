<?php

namespace Dakataa\Security\TwoFactorAuthenticator\EventHandler\Listener;


use Dakataa\Security\TwoFactorAuthenticator\Authentication\Token\TwoFactorAuthenticationToken;
use Dakataa\Security\TwoFactorAuthenticator\EventHandler\Event\TwoFactorActivateEvent;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticatorProvider;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Config\Definition\Exception\Exception;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
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
        private readonly HttpUtils $httpUtils,
        private readonly RouterInterface $router,
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
        $twoFactorEntity = $this->twoFactorProvider->getEntity($parentToken->getUser());
        if(!$twoFactorEntity || false === $twoFactorEntity->isTwoFactorActive()) {
            return;
        }

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
        $response = match ($this->getResponseType($request)) {
            'json' => new JsonResponse([
                'challenge' => [
                    'type' => $twoFactorEntity->getTwoFactorAuthenticator(),
                    'url' => $this->httpUtils->generateUri(
                        $request,
                        $this->parameterBag->get('dakataa_two_factor_authenticator.check_path')
                    ),
                    'required_fields' => [
                        ...(!$request->getSession()->isStarted() ? [
                            $this->parameterBag->get(
                                'dakataa_two_factor_authenticator.username_parameter'
                            ),
                        ] : []),
                        $this->parameterBag->get('dakataa_two_factor_authenticator.code_parameter'),
                    ],
                ],
            ]),
            default => (function () use ($request) {
                return $this->httpUtils->createRedirectResponse(
                    $request,
                    $this->httpUtils->generateUri($request, $this->getCodeFormPath())
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
        $codeCheckRoute = $this->parameterBag->get('dakataa_two_factor_authenticator.check_path');
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
            $codeParameterAccessorPath = $getAccessorPath('dakataa_two_factor_authenticator.code_parameter');
            $usernameParameterAccessorPath = $getAccessorPath('dakataa_two_factor_authenticator.username_parameter');

            $requestData = match ($this->getResponseType($request)) {
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

            $username = $request->getSession()->isStarted() ? $request->getSession()->get(SecurityRequestAttributes::LAST_USERNAME) : $propertyAccessor->getValue($requestData, $usernameParameterAccessorPath);
            $code = $propertyAccessor->getValue($requestData, $codeParameterAccessorPath);

            if (!$username) {
                throw new AuthenticationException('Invalid Username.');
            }

            if (!$code) {
                throw new AuthenticationException('Invalid Auth Code.');
            }

            $user = $this->userProvider->loadUserByIdentifier($username);
            $twoFactorAuthenticator = $this->twoFactorProvider->getAuthenticator($user);
            if (!$twoFactorAuthenticator) {
                throw new AuthenticationException('Two Factor Authenticator not configured for this user.');
            }

            $twoFactorEntity = $this->twoFactorProvider->getEntity($user);
            if (!$twoFactorAuthenticator->isDispatched($twoFactorEntity)) {
                throw new AuthenticationException('Two Factor Authentication is not dispatched.');
            }

            if (!$twoFactorAuthenticator->validate(
                $twoFactorEntity,
                $code
            )) {
                throw new AuthenticationException(
                    'Invalid 2FA Credentials.'
                );
            }

            if ($twoFactorEntity->isTwoFactorActive()) {
                $response = $this->security->login($user, firewallName: $this->parameterBag->get('dakataa_two_factor_authenticator.firewall'));
                if(!$response) {
                    throw new Exception('Two Factor Authenticator failed to authenticate. Provide correct firewall in configuration.');
                }
                $event->setResponse($response);
            } else {
                $activationEvent = $this->eventDispatcher->dispatch(new TwoFactorActivateEvent($user, $twoFactorEntity));
                $response = $activationEvent->getResponse() ?: match ($this->getResponseType($request)) {
                    'json' => new JsonResponse([
                        'message' => 'Successful 2FA setup.',
                    ]),
                    default => new RedirectResponse($this->getTargetPath($request))
                };

                $event->setResponse($response);
            }
        } catch (AuthenticationException $e) {
            if ($request->getSession()->isStarted()) {
                $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $e);
            }

            match ($this->getResponseType($request)) {
                'json' => $event->setResponse(new JsonResponse([
                    'message' => 'Invalid 2FA Credentials',
                    'originalMessage' => $e->getMessage(),
                    'requirements' => [
                        'twoFactorAuthenticator' => [
                            'fields' => [
                                ...(!$request->getSession()->isStarted() ? [
                                    $this->parameterBag->get(
                                        'dakataa_two_factor_authenticator.username_parameter'
                                    ),
                                ] : []),
                                $this->parameterBag->get('dakataa_two_factor_authenticator.code_parameter'),
                            ],
                        ],
                    ],
                ], 400)),
                default => $event->setResponse($this->httpUtils->createRedirectResponse(
                    $request,
                    $this->httpUtils->generateUri($request, $this->getCodeFormPath())
                ))
            };
        }
    }

    private function getResponseType(Request $request): string
    {
        return $request->getContentTypeFormat() ?: $request->getRequestFormat();
    }

    private function getCodeFormPath(): string
    {
        $route = $this->parameterBag->get('dakataa_two_factor_authenticator.form_path');

        try {
            if (!$this->router->getRouteCollection()->get($route)) {
                $this->router->match($route);
            }
        } catch (Throwable) {
            throw new InvalidConfigurationException(sprintf('Missing route for 2FA code form: %s', $route));
        }

        return $route;
    }

    private function getTargetPath(Request $request): string
    {
        return $request->query->get(
            $this->parameterBag->get('dakataa_two_factor_authenticator.target.parameter'),
            $this->parameterBag->get('dakataa_two_factor_authenticator.target.path_default')
        );
    }
}
