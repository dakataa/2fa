<?php

namespace Dakataa\Security\TwoFactorAuthenticator\Session\Storage;

use Dakataa\Security\TwoFactorAuthenticator\Session\TwoFactorSessionInterface;
use Dakataa\Security\TwoFactorAuthenticator\TwoFactorAuthenticatorEntityInterface;
use DateInterval;
use Exception;
use Psr\Cache\CacheItemPoolInterface;

class TwoFactorAuthenticatorStorage implements TwoFactorAuthenticatorSessionStorageInterface
{

    public function __construct(private readonly CacheItemPoolInterface $twoFactorAuthenticatorCache)
    {
    }

    public function has(TwoFactorAuthenticatorEntityInterface $entity): bool
    {
        return $this->twoFactorAuthenticatorCache->hasItem($this->getItemKey($entity));
    }

    public function get(TwoFactorAuthenticatorEntityInterface $entity): TwoFactorSessionInterface
    {
        if (!$this->has($entity)) {
            throw new Exception('Missing 2FA Session.');
        }

        $cacheItem = $this->twoFactorAuthenticatorCache->getItem($this->getItemKey($entity));
        $data = $cacheItem->get();
        if (false === $data instanceof TwoFactorSessionInterface) {
            throw new Exception('Invalid Session');
        }

        return $data;
    }


    public function set(
        TwoFactorAuthenticatorEntityInterface $entity,
        TwoFactorSessionInterface $session
    ): void {

        $item = $this->twoFactorAuthenticatorCache->getItem($this->getItemKey($entity));

        $item->set($session)
            ->expiresAfter(new DateInterval(sprintf('PT%dS', $session->getTTL())));

        $this
            ->twoFactorAuthenticatorCache
            ->save($item);
    }

    public function invalidate(TwoFactorAuthenticatorEntityInterface $entity): void
    {
        $this->twoFactorAuthenticatorCache->deleteItem($this->getItemKey($entity));
    }

    private function getItemKey(TwoFactorAuthenticatorEntityInterface $entity): string
    {
        return sha1($entity->getTwoFactorIdentifier());
    }
}
