<?php

namespace Drupal\openid_connect_windows_aad\Controller;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Controller\ControllerBase;
use Drupal\externalauth\AuthmapInterface;
use Drupal\openid_connect\Entity\OpenIDConnectClientEntity;
use Drupal\openid_connect\OpenIDConnectSession;
use Drupal\openid_connect_windows_aad\Plugin\OpenIDConnectClient\WindowsAad;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * Controller routines for Azure AD single sign out user routes.
 */
class WindowsAadSSOController extends ControllerBase {

  /**
   * A logger instance.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /*
   * The authmap storage.
   *
   * @var \Drupal\externalauth\AuthmapInterface $authmap
   */
  protected $authmap;

  /**
   * Constructs a WindowsAadSSOController object.
   *
   * @param \Psr\Log\LoggerInterface $logger
   *   A logger instance.
   * @param \Drupal\externalauth\AuthmapInterface $authmap
   */
  public function __construct(LoggerInterface $logger, AuthmapInterface $authmap, OpenIDConnectSession $openIDConnectSession, ConfigFactoryInterface $configFactory) {
    $this->logger = $logger;
    $this->authmap = $authmap;
    $this->openIDConnectSession = $openIDConnectSession;
    $this->configFactory = $configFactory;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('logger.factory')->get('openid_connect_windows_aad'),
      $container->get('externalauth.authmap'),
      $container->get('openid_connect.session'),
      $container->get('config.factory'),
    );
  }

  /**
   * Single Sign Out callback to log the current user out.
   *
   * Called by Windows Azure AD when a user logs out of their SSO session from
   * another application such as Office 365.
   *
   * @return \Symfony\Component\HttpFoundation\Response
   *   Either a 200 or 403 response without any content.
   */
  public function signout() {
    if ($this->currentUser()->isAnonymous()) {
      return new Response('', Response::HTTP_OK);
    }

    $config = $this->configFactory->get('openid_connect.settings');
    $mapped_users = $this->authmap->getAll($this->currentUser->id());
    if (is_array($mapped_users) & !empty($mapped_users)) {
      foreach (array_keys($mapped_users) as $key) {
        // strlen('openid_connect.') = 15.
        $client_name = substr($key, 15);
        $client = OpenIDConnectClientEntity::load($client_name);
        if ($client->getPlugin() instanceof WindowsAad) {
          $endpoints = $client->getPlugin()->getEndpoints();
          // Destroy session if provider supports it.
          $end_session_enabled = $config->get('end_session_enabled') ?? FALSE;
          if ($end_session_enabled && !empty($endpoints['end_session'])) {
            user_logout();
            return new Response('', Response::HTTP_OK);
          }
        }
      }
    }

    // Likely a misconfiguration since SSOut attempts should not be made to the
    // logout uri unless it has been configured in Azure AD; if you had
    // configured it in Azure AD then you should have also enabled SSOut in the
    // OpenID Connect settings. Also, a possible malicious CSRF attempt. Log a
    // warning either way.
    $this->logger->warning('Windows AAD Single Sign Out attempt, but SSOut has not been enabled in the OpenID Connect Windows AAD configuration.');
    return new Response('', Response::HTTP_FORBIDDEN);
  }

}
