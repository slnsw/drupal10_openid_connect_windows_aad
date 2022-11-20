<?php

namespace Drupal\openid_connect_windows_aad\Plugin\OpenIDConnectClient;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Language\LanguageInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\PageCache\ResponsePolicy\KillSwitch;
use Drupal\key\KeyRepositoryInterface;
use Drupal\openid_connect\OpenIDConnectAutoDiscover;
use Drupal\openid_connect\OpenIDConnectStateTokenInterface;
use Drupal\openid_connect\Plugin\OpenIDConnectClientBase;
use Drupal\Core\Url;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\RequestException;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

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
   * The key repository interface.
   *
   * @var \Drupal\key\KeyRepositoryInterface
   */
  protected $keyRepository;

  /**
   * The constructor.
   *
   * @param array $configuration
   *   The plugin configuration.
   * @param string $plugin_id
   *   The plugin identifier.
   * @param mixed $plugin_definition
   *   The plugin definition.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request_stack
   *   The request stack.
   * @param \GuzzleHttp\ClientInterface $http_client
   *   The http client.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   * @param \Drupal\key\KeyRepositoryInterface $key_repository
   *   The Key Repository interface.
   */
  public function __construct(array $configuration, string $plugin_id, $plugin_definition, RequestStack $request_stack, ClientInterface $http_client, LoggerChannelFactoryInterface $logger_factory, TimeInterface $datetime_time, KillSwitch $page_cache_kill_switch, LanguageManagerInterface $language_manager, OpenIDConnectStateTokenInterface $state_token, OpenIDConnectAutoDiscover $auto_discover, KeyRepositoryInterface $key_repository) {
    parent::__construct($configuration, $plugin_id, $plugin_definition, $request_stack, $http_client, $logger_factory, $datetime_time, $page_cache_kill_switch, $language_manager, $state_token, $auto_discover);
    $this->keyRepository = $key_repository;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('request_stack'),
      $container->get('http_client'),
      $container->get('logger.factory'),
      $container->get('datetime.time'),
      $container->get('page_cache_kill_switch'),
      $container->get('language_manager'),
      $container->get('openid_connect.state_token'),
      $container->get('openid_connect.autodiscover'),
      $container->get('key.repository')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function defaultConfiguration(): array {
    return [
        'authorization_endpoint_wa' => '',
        'token_endpoint_wa' => '',
        'userinfo_endpoint_wa' => '',
        'enable_single_sign_out' => FALSE,
        'map_ad_groups_to_roles' => FALSE,
        'group_mapping' => [
          'method' => 0,
          'mappings' => '',
          'strict' => FALSE,
        ],
        'userinfo_graph_api_wa' => 0,
        'userinfo_graph_api_use_other_mails' => FALSE,
        'userinfo_update_email' => FALSE,
        'hide_email_address_warning' => FALSE,
      ] + parent::defaultConfiguration();
  }

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state): array {
    $form = parent::buildConfigurationForm($form, $form_state);
    $form['enable_single_sign_out'] = [
      '#title' => $this->t('Enable Single Sign Out'),
      '#type' => 'checkbox',
      '#default_value' => $this->configuration['enable_single_sign_out'],
      '#description' => $this->t('Checking this option will enable Single Sign Out to occur so long as the logout url has been set to (http(s)://yoursite.com/openid-connect/windows_aad/signout) in your Azure AD registered app settings. If a user logs out of the Drupal app then they will be logged out of their SSO session elsewhere as well. Conversely if a user signs out of their SSO account elsewhere, such as Office 365, they will also be logged out of this app.'),
    ];
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
    $form['map_ad_groups_to_roles'] = [
      '#title' => $this->t("Map user's AD groups to Drupal roles"),
      '#type' => 'checkbox',
      '#default_value' => $this->configuration['map_ad_groups_to_roles'],
      '#description' => $this->t('Enable this to configure Drupal user role assignment based on AD group membership.'),
    ];
    // AD group mapping configuration field set.
    $form['group_mapping'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('AD group mapping options'),
      '#states' => [
        'invisible' => [
          ':input[name="settings[map_ad_groups_to_roles]"]' => ['checked' => FALSE],
        ],
      ],
    ];
    $form['group_mapping']['method'] = [
      '#type' => 'radios',
      '#title' => $this->t('Method for mapping AD groups to roles'),
      '#options' => [
        0 => $this->t('Automatic (AD group names or ids identically match Drupal role names)'),
        1 => $this->t('Manual (Specify which AD groups map to which Drupal roles)'),
      ],
      '#default_value' => $this->configuration['group_mapping']['method'],
      '#description' => $this->t('Note: For name mapping to function the Azure AD Graph or Microsoft Graph APIs must be selected as a User endpoint. Otherwise only mapping based on Group Object IDs can be used.'),
    ];
    $form['group_mapping']['mappings'] = [
      '#title' => $this->t('Manual mappings'),
      '#type' => 'textarea',
      '#default_value' => $this->configuration['group_mapping']['mappings'],
      '#description' => $this->t('Add one role|group(s) mapping per line. Role and Group should be separated by "|". Multiple groups can be mapped to a single role on the same line using ";" to separate the groups. Ideally you should use the group id since it is immutable, but the title (displayName) may also be used.'),
      '#states' => [
        'invisible' => [
          ':input[name="clients[windows_aad][settings][group_mapping][method]"]' => ['value' => 0],
        ],
      ],
    ];
    $form['group_mapping']['strict'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Only allow users to have roles that map to an AD group they are a member of.'),
      '#default_value' => $this->configuration['group_mapping']['strict'],
      '#description' => $this->t('Removes roles from a Drupal user account that do not map to AD groups the user is a member of. Also, with this enabled you can not grant unmapped roles to a user through the usual Drupal user/role interface such as editing a user account. Note: Only affects users with connected AD accounts.'),
    ];
    $form['userinfo_graph_api_wa'] = [
      '#title' => $this->t('User info endpoint configuration'),
      '#type' => 'radios',
      '#default_value' => $this->configuration['userinfo_graph_api_wa'],
      '#options' => [
        0 => $this->t('Alternate or no user endpoint'),
        1 => $this->t('Azure AD Graph API (v1.6)'),
        2 => $this->t('Microsoft Graph API (v1.0)'),
      ],
      '#description' => $this->t('Most user/group info can be returned in the access token response through proper claims/permissions configuration for your app registration within Azure AD. If this is the case for your setup then you can choose "Alternate or no user endpoint" and leave blank the dependent "Alternate userinfo endpoint" text box. Otherwise you can choose to use the Azure AD graph API or the Microsoft Graph API (recommended) to retrieve user and/or graph info.'),
    ];
    $form['userinfo_endpoint_wa'] = [
      '#title' => $this->t('Alternate UserInfo endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_endpoint_wa'],
      '#states' => [
        'visible' => [
          ':input[name="clients[windows_aad][settings][userinfo_graph_api_wa]"]' => ['value' => 0],
        ],
      ],
    ];
    $form['userinfo_graph_api_use_other_mails'] = [
      '#title' => $this->t('Use Graph API otherMails property for email address'),
      '#type' => 'checkbox',
      '#default_value' => $this->configuration['userinfo_graph_api_use_other_mails'],
      '#description' => $this->t('Find the first occurrence of an email address in the Graph otherMails property and use this as email address.'),
      '#states' => [
        'visible' => [
          ':input[name="clients[windows_aad][settings][userinfo_graph_api_wa]"]' => ['value' => 1],
        ],
      ],
    ];
    $form['userinfo_update_email'] = [
      '#title' => $this->t('Update email address in user profile'),
      '#type' => 'checkbox',
      '#default_value' => $this->configuration['userinfo_update_email'],
      '#description' => $this->t('If email address has been changed for existing user, save the new value to the user profile.'),
    ];
    $form['hide_email_address_warning'] = [
      '#title' => $this->t('Hide missing email address warning'),
      '#type' => 'checkbox',
      '#default_value' => $this->configuration['hide_email_address_warning'],
      '#description' => $this->t('By default, when email address is not found, a message will appear on the screen. This option hides that message (as it might be confusing for end users).'),
    ];

    $form['client_secret'] = [
      '#title' => $this->t('Client secret'),
      '#type' => 'key_select',
      '#default_value' => $this->configuration['client_secret'],
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function getEndpoints() : array {
    return [
      'authorization' => $this->configuration['authorization_endpoint_wa'],
      'token' => $this->configuration['token_endpoint_wa'],
      'userinfo' => $this->configuration['userinfo_endpoint_wa'],
    ];
  }

  /**
   * {@inheritdoc}
   */
  protected function getRequestOptions(string $authorization_code, string $redirect_uri): array {
    $options = parent::getRequestOptions($authorization_code, $redirect_uri);
    $options['form_params']['client_secret'] = $this->keyRepository->getKey($this->configuration['client_secret'])->getKeyValue();
    return $options;
  }

  /**
   * {@inheritdoc}
   */
  public function retrieveTokens(string $authorization_code): ?array {
    // Exchange `code` for access token and ID token.
    $redirect_uri = $this->getRedirectUrl()->toString();
    $endpoints = $this->getEndpoints();
    $request_options = $this->getRequestOptions($authorization_code, $redirect_uri);

    // Add a Graph API as resource if an option is selected.
    switch ($this->configuration['userinfo_graph_api_wa']) {
      case 1:
        $request_options['form_params']['resource'] = 'https://graph.windows.net';
        break;

      case 2:
        $request_options['form_params']['resource'] = 'https://graph.microsoft.com';
        break;
    }

    $client = $this->httpClient;

    try {
      $response = $client->post($endpoints['token'], $request_options);
      $response_data = json_decode((string) $response->getBody(), TRUE);

      // Expected result.
      $tokens = [
        'id_token' => $response_data['id_token'],
        'access_token' => $response_data['access_token'],
        'refresh_token' => isset($response_data['refresh_token']) ? $response_data['refresh_token'] : FALSE,
      ];
      if (array_key_exists('expires_in', $response_data)) {
        $tokens['expire'] = \Drupal::time()
            ->getRequestTime() + $response_data['expires_in'];
      }
      return $tokens;
    } catch (RequestException $e) {
      $variables = [
        '@message' => 'Could not retrieve tokens',
        '@error_message' => $e->getMessage(),
      ];
      $this->loggerFactory->get('openid_connect_windows_aad')
        ->error('@message. Details: @error_message', $variables);
    }
    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function retrieveUserInfo(string $access_token): ?array {

    // Determine if we use Graph API or default O365 Userinfo as this will
    // affect the data we collect and use in the Userinfo array.
    switch ($this->configuration['userinfo_graph_api_wa']) {
      case 1:
        $userinfo = $this->buildUserinfo($access_token, 'https://graph.windows.net/me?api-version=1.6', 'userPrincipalName', 'displayName');
        break;

      case 2:
        $userinfo = $this->buildUserinfo($access_token, 'https://graph.microsoft.com/v1.0/me', 'userPrincipalName', 'displayName');
        break;

      default:
        $endpoints = $this->getEndpoints();
        if ($endpoints['userinfo']) {
          $userinfo = $this->buildUserinfo($access_token, $endpoints['userinfo'], 'upn', 'name');
        }
        else {
          $userinfo = [];
        }
        break;
    }

    // If AD group to Drupal role mapping has been enabled then attach group
    // data from a graph API if configured to do so.
    if ($this->configuration['map_ad_groups_to_roles']) {
      $userinfo['groups'] = $this->retrieveGroupInfo($access_token);
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
   *   The userinfo array. Empty array if unsuccessful.
   */
  private function buildUserinfo($access_token, $url, $upn, $name) {
    $profile_data = [];

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

      // Azure provides 'mail' for userinfo vs email.
      if (!isset($profile_data['mail'])) {
        // See if we have the Graph otherMails property and use it if available,
        // if not, add the principal name as email instead, so Drupal still will
        // create the user anyway.
        if ($this->configuration['userinfo_graph_api_use_other_mails']) {
          if (!empty($profile_data['otherMails'])) {
            // Use first occurrence of otherMails attribute.
            $profile_data['email'] = current($profile_data['otherMails']);
          }
        }
        else {
          // Show message to user.
          if (!$this->configuration['hide_email_address_warning']) {
            \Drupal::messenger()
              ->addWarning(t('Email address not found in UserInfo. Used username instead, please check this in your profile.'));
          }
          // Write watchdog warning.
          $variables = ['@user' => $profile_data[$upn]];

          $this->loggerFactory->get('openid_connect_windows_aad')
            ->warning('Email address of user @user not found in UserInfo. Used username instead, please check.', $variables);

          $profile_data['email'] = $profile_data[$upn];
        }
      }
      else {
        // OpenID Connect module expects the 'email' token for userinfo.
        $profile_data['email'] = $profile_data['mail'];
      }

    } catch (RequestException $e) {
      $variables = [
        '@error_message' => $e->getMessage(),
      ];
      $this->loggerFactory->get('openid_connect_windows_aad')
        ->error('Could not retrieve user profile information. Details: @error_message', $variables);
    }
    return $profile_data;
  }

  /**
   * Calls a graph api to retrieve teh user's group membership information.
   *
   * @param string $access_token
   *   An access token string.
   *
   * @return array
   *   An array of group informaion.
   */
  protected function retrieveGroupInfo($access_token) {
    // By default or if an error occurs return empty group information.
    $group_data = [];

    switch ($this->configuration['userinfo_graph_api_wa']) {
      case 1:
        $uri = 'https://graph.windows.net/me/memberOf?api-version=1.6';
        break;

      case 2:
        $uri = 'https://graph.microsoft.com/v1.0/me/memberOf';
        break;

      default:
        $uri = FALSE;
        break;
    }

    if ($uri) {
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
        $response = $client->get($uri, $options);
        $response_data = (string) $response->getBody();

        // Group Information.
        $group_data = json_decode($response_data, TRUE);
      } catch (RequestException $e) {
        $variables = [
          '@api' => $uri,
          '@error_message' => $e->getMessage(),
        ];
        $this->loggerFactory->get('openid_connect_windows_aad')
          ->error('Failed to retrieve AD group information from graph api (@api). Details: @error_message', $variables);
      }
    }
    // Return group information or an empty array.
    return $group_data;
  }

}
