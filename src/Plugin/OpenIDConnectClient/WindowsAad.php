<?php

namespace Drupal\openid_connect_windows_aad\Plugin\OpenIDConnectClient;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Language\LanguageInterface;
use Drupal\openid_connect\Plugin\OpenIDConnectClientBase;
use Drupal\Core\Url;
use GuzzleHttp\Exception\RequestException;

/**
 * Generic OpenID Connect client.
 *
 * Used primarily to login to Drupal sites powered by oauth2_server or PHP
 * sites powered by oauth2-server-php.
 *
 * @OpenIDConnectClient(
 *   id = "windows_aad",
 *   label = @Translation("Windows Azure AD")
 * )
 */
class WindowsAad extends OpenIDConnectClientBase {

  /**
   * Overrides OpenIDConnectClientBase::settingsForm().
   *
   * @param array $form
   *   Windows AAD form array containing form elements.
   *
   * @param FormStateInterface $form_state
   *   Submitted form values.
   *
   * @return array
   *   Renderable form array with form elements.
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $form = parent::buildConfigurationForm($form, $form_state);
    $form['authorization_endpoint_wa'] = [
      '#title' => $this->t('Authorization endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['authorization_endpoint_wa'],
    ];
    $form['token_endpoint_wa'] = [
      '#title' => $this->t('Token endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['token_endpoint_wa'],
    ];
    $form['userinfo_endpoint_wa'] = [
      '#title' => $this->t('UserInfo endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_endpoint_wa'],
    ];
    $form['userinfo_graph_api_wa'] = [
      '#title' => $this->t('Use Graph API for user info'),
      '#type' => 'checkbox',
      '#default_value' => !empty($this->configuration['userinfo_graph_api_wa']) ? $this->configuration['userinfo_graph_api_wa'] : '',
      '#description' => $this->t('This option will omit the Userinfo endpoint and will use the Graph API ro retrieve the userinfo.'),
    ];
    $form['userinfo_graph_api_use_other_mails'] = [
      '#title' => $this->t('Use Graph API otherMails property for email address'),
      '#type' => 'checkbox',
      '#default_value' => !empty($this->configuration['userinfo_graph_api_use_other_mails']) ? $this->configuration['userinfo_graph_api_use_other_mails'] : '',
      '#description' => $this->t('Find the first occurrence of an email address in the Graph otherMails property and use this as email address.'),
    ];
    $form['userinfo_update_email'] = [
      '#title' => $this->t('Update email address in user profile'),
      '#type' => 'checkbox',
      '#default_value' => !empty($this->configuration['userinfo_update_email']) ? $this->configuration['userinfo_update_email'] : '',
      '#description' => $this->t('If email address has been changed for existing user, save the new value to the user profile.'),
    ];
    $form['hide_email_address_warning'] = [
      '#title' => $this->t('Hide missing email address warning'),
      '#type' => 'checkbox',
      '#default_value' => !empty($this->configuration['hide_email_address_warning']) ? $this->configuration['hide_email_address_warning'] : '',
      '#description' => $this->t('By default, when email address is not found, a message will appear on the screen. This option hides that message (as it might be confusing for end users).'),
    ];

    return $form;
  }

  /**
   * Overrides OpenIDConnectClientBase::getEndpoints().
   *
   * @return array
   *  Endpoint details with authorization endpoints, user access token and
   *  userinfo object.
   */
  public function getEndpoints() {
    return [
      'authorization' => $this->configuration['authorization_endpoint_wa'],
      'token' => $this->configuration['token_endpoint_wa'],
      'userinfo' => $this->configuration['userinfo_endpoint_wa'],
    ];
  }

  /**
   * Implements OpenIDConnectClientInterface::retrieveIDToken().
   *
   * @param string $authorization_code
   *   A authorization code string.
   *
   * @return array|bool
   *   A result array or false.
   */
  public function retrieveTokens($authorization_code) {
    // Exchange `code` for access token and ID token.
    $language_none = \Drupal::languageManager()
      ->getLanguage(LanguageInterface::LANGCODE_NOT_APPLICABLE);
    $redirect_uri = Url::fromRoute(
      'openid_connect.redirect_controller_redirect',
      [
        'client_name' => $this->pluginId,
      ],
      [
        'absolute' => TRUE,
        'language' => $language_none,
      ]
    )->toString();
    $endpoints = $this->getEndpoints();

    $request_options = [
      'form_params' => [
        'code' => $authorization_code,
        'client_id' => $this->configuration['client_id'],
        'client_secret' => $this->configuration['client_secret'],
        'redirect_uri' => $redirect_uri,
        'grant_type' => 'authorization_code',
      ],
    ];

    // Add Graph API as resource if option is set.
    if ($this->configuration['userinfo_graph_api_wa'] == 1) {
      $request_options['form_params']['resource'] = 'https://graph.windows.net';
    }

    /* @var \GuzzleHttp\ClientInterface $client */
    $client = $this->httpClient;

    try {
      $response = $client->post($endpoints['token'], $request_options);
      $response_data = json_decode((string) $response->getBody(), TRUE);

      // Expected result.
      $tokens = [
        'id_token' => $response_data['id_token'],
        'access_token' => $response_data['access_token'],
      ];
      if (array_key_exists('expires_in', $response_data)) {
        $tokens['expire'] = REQUEST_TIME + $response_data['expires_in'];
      }
      return $tokens;
    }
    catch (RequestException $e) {
      $variables = [
        '@message' => 'Could not retrieve tokens',
        '@error_message' => $e->getMessage(),
      ];
      $this->loggerFactory->get('openid_connect_windows_aad')
        ->error('@message. Details: @error_message', $variables);
      return FALSE;
    }
  }

  /**
   * Implements OpenIDConnectClientInterface::retrieveUserInfo().
   *
   * @param string $access_token
   *   An access token string.
   *
   * @return array|bool
   *   A result array or false.
   */
  public function retrieveUserInfo($access_token) {

    // Determine if we use Graph API or default O365 Userinfo as this will
    // affect the data we collect and use in the Userinfo array.
    switch ($this->configuration['userinfo_graph_api_wa']) {
      case 1:
        $userinfo = $this->buildUserinfo($access_token, 'https://graph.windows.net/me?api-version=1.6', 'userPrincipalName', 'displayName');
        break;

      default:
        $endpoints = $this->getEndpoints();
        $userinfo = $this->buildUserinfo($access_token, $endpoints['userinfo'], 'upn', 'name');
        break;
    }

    // Check to see if we have changed email data, O365_connect doesn't
    // give us the possibility to add a mapping for it, so we do the change
    // now, first checking if this is wanted by checking the setting for it.
    if ($this->configuration['userinfo_update_email'] == 1) {
      /** @var \Drupal\user\UserInterface $user */
      $user = user_load_by_name($userinfo['name']);

      if ($user && ($user->getEmail() != $userinfo['email'])) {
        $user->setEmail($userinfo['email']);
        $user->save();
      }
    }

    return $userinfo;
  }

  /**
   * Helper function to do the call to the endpoint and build userinfo array.
   *
   * @param string $access_token
   *   The access token.
   * @param string $url
   *   The endpoint we want to send the request to.
   * @param string $upn
   *   The name of the property that holds the Azure username.
   * @param string $name
   *   The name of the property we want to map to Drupal username.
   *
   * @return array
   *   The userinfo array or FALSE.
   */
  private function buildUserinfo($access_token, $url, $upn, $name) {
    // Perform the request.
    $options = [
      'method' => 'GET',
      'headers' => [
        'Content-Type' => 'application/json',
        'Authorization' => 'Bearer ' . $access_token,
      ],
    ];
    $client = $this->httpClient;

    try {
      $response = $client->get($url, $options);
      $response_data = (string) $response->getBody();

      // Profile Information.
      $profile_data = json_decode($response_data, TRUE);
      $profile_data['name'] = $profile_data[$name];

      if (!isset($profile_data['email'])) {
        // See if we have the Graph otherMails property and use it if available,
        // if not, add the principal name as email instead, so Drupal still will
        // create the user anyway.
        if ($this->configuration['userinfo_graph_api_use_other_mails'] == 1) {
          if (!empty($profile_data['otherMails'])) {
            // Use first occurrence of otherMails attribute.
            $profile_data['email'] = current($profile_data['otherMails']);
          }
        }
        else {
          // Show message to user.
          if ($this->configuration['hide_email_address_warning'] <> 1) {
            drupal_set_message(t('Email address not found in UserInfo. Used username instead, please check this in your profile.'), 'warning');
          }
          // Write watchdog warning.
          $variables = ['@user' => $profile_data[$upn]];

          $this->loggerFactory->get('openid_connect_windows_aad')
            ->warning('Email address of user @user not found in UserInfo. Used username instead, please check.', $variables);

          $profile_data['email'] = $profile_data[$upn];
        }
      }
      return $profile_data;
    }
    catch (RequestException $e) {
      $variables = [
        '@message' => 'Could not retrieve user profile information',
        '@error_message' => $e->getMessage(),
      ];
      $this->loggerFactory->get('openid_connect_windows_aad')
        ->error('@message. Details: @error_message', $variables);
      return FALSE;
    }
  }

}
