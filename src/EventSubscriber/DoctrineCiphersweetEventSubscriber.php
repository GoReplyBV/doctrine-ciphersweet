<?php

namespace GoReply\DoctrineCiphersweet\EventSubscriber;

use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\Event\OnFlushEventArgs;
use Doctrine\ORM\Event\PostFlushEventArgs;
use Doctrine\ORM\Event\PostLoadEventArgs;
use Doctrine\ORM\Event\PostUpdateEventArgs;
use Doctrine\ORM\Event\PreFlushEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\ORM\Events;
use GoReply\DoctrineCiphersweet\Helper;

class DoctrineCiphersweetEventSubscriber implements EventSubscriber
{
    public function __construct(
        private Helper $helper
    ) {
    }

    public function getSubscribedEvents(): array
    {
        return [
            Events::postUpdate,
            Events::preUpdate,
            Events::postLoad,
            Events::onFlush,
            Events::preFlush,
            Events::postFlush,
        ];
    }

    public function postUpdate(PostUpdateEventArgs $args): void
    {
        $this->helper->decrypt($args->getObject());
    }

    public function preUpdate(PreUpdateEventArgs $args): void
    {
        $this->helper->encrypt($args->getObject());
    }

    public function postLoad(PostLoadEventArgs $args): void
    {
        $this->helper->decrypt($args->getObject());
    }

    public function preFlush(PreFlushEventArgs $args): void
    {
        $uow = $args->getObjectManager()->getUnitOfWork();

        foreach ($uow->getIdentityMap() as $entities) {
            foreach ($entities as $entity) {
                if ($entity === null) {
                    continue;
                }

                $this->helper->encrypt($entity);
            }
        }
    }

    public function onFlush(OnFlushEventArgs $args): void
    {
        $om = $args->getObjectManager();
        $uow = $om->getUnitOfWork();

        foreach ($uow->getScheduledEntityInsertions() as $entity) {
            if (!$this->helper->hasEncryptedFields($entity::class)) {
                continue;
            }

            $this->helper->encrypt($entity);

            $classMetadata = $om->getClassMetadata($entity::class);
            $uow->recomputeSingleEntityChangeSet($classMetadata, $entity);
        }
    }

    public function postFlush(PostFlushEventArgs $args): void
    {
        $uow = $args->getObjectManager()->getUnitOfWork();

        foreach ($uow->getIdentityMap() as $entities) {
            foreach ($entities as $entity) {
                if ($entity === null) {
                    continue;
                }

                $this->helper->decrypt($entity);
            }
        }
    }
}
