<?php

namespace Drupal\openid_connect_windows_aad\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\externalauth\AuthmapInterface;
use Psr\Log\LoggerInterface;
use Drupal\Component\Utility\UrlHelper;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
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
  public function __construct(LoggerInterface $logger, AuthmapInterface $authmap) {
    $this->logger = $logger;
    $this->authmap = $authmap;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('logger.factory')->get('openid_connect_windows_aad'),
      $container->get('externalauth.authmap')
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
    $configuration = $this->config('openid_connect.client.windows_aad');
    $settings = $configuration->get('settings');
    $enabled = $configuration->get('status');
    // Check that the windows_aad client is enabled and so is SSOut.
    if ($enabled && isset($settings['enable_single_sign_out']) && $settings['enable_single_sign_out']) {
      // Ensure the user has a connected account.
      $user = \Drupal::currentUser();
      $connected_accounts = $this->authmap->getAll($user->id());
      $connected = ($connected_accounts && isset($connected_accounts['windows_aad']));
      $logged_in = $user->isAuthenticated();
      // Only log the user out if they are logged in and have a connected
      // account. Return a 200 OK in any case since all is good.
      if ($logged_in && $connected) {
        user_logout();
      }
      return new Response('', Response::HTTP_OK);
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
