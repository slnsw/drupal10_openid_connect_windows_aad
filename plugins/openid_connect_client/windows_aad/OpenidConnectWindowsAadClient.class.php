<?php


/**
 * @file
 * OpenID Connect client for Windows Azure AD.
 */

/**
 * Class OpenidConnectWindowsAadClient adds the client to OpenID Connect.
 */
class OpenidConnectWindowsAadClient extends OpenIDConnectClientBase {

  /**
   * Overrides OpenIDConnectClientBase::settingsForm().
   */
  public function settingsForm() {
    $form = parent::settingsForm();

    $default_site = 'https://login.windows.net/[tenant]';
    $form['authorization_endpoint_wa'] = array(
      '#title' => t('Authorization endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('authorization_endpoint_wa', $default_site . '/oauth2/authorize'),
    );
    $form['token_endpoint_wa'] = array(
      '#title' => t('Token endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('token_endpoint_wa', $default_site . '/oauth2/token'),
    );
    $form['userinfo_endpoint_wa'] = array(
      '#title' => t('UserInfo endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('userinfo_endpoint_wa', $default_site . '/openid/userinfo'),
    );
    $form['userinfo_graph_api_wa'] = array(
      '#title' => t('Use Graph API for user info'),
      '#type' => 'checkbox',
      '#default_value' => $this->getSetting('userinfo_graph_api_wa'),
      '#description' => t('This option will omit the Userinfo endpoint and will use the Graph API ro retrieve the userinfo.'),
    );

    return $form;
  }


  /**
   * Overrides OpenIDConnectClientBase::getEndpoints().
   */
  public function getEndpoints() {
    return array(
      'authorization' => $this->getSetting('authorization_endpoint_wa'),
      'token' => $this->getSetting('token_endpoint_wa'),
      'userinfo' => $this->getSetting('userinfo_endpoint_wa'),
    );
  }

  /**
   * Overrides OpenIDConnectClientInterface::retrieveIDToken().
   */
  public function retrieveTokens($authorization_code) {
    // Exchange `code` for access token and ID token.
    $redirect_uri = OPENID_CONNECT_REDIRECT_PATH_BASE . '/' . $this->name;
    $post_data = array(
      'code' => $authorization_code,
      'client_id' => $this->getSetting('client_id'),
      'client_secret' => $this->getSetting('client_secret'),
      'redirect_uri' => url($redirect_uri, array('absolute' => TRUE)),
      'grant_type' => 'authorization_code',
    );

    // Add Graph API as resource if option is set.
    if ($this->getSetting('userinfo_graph_api_wa') == 1) {
      $post_data['resource'] = 'https://graph.windows.net';
    }

    $request_options = array(
      'method' => 'POST',
      'data' => drupal_http_build_query($post_data),
      'timeout' => 15,
      'headers' => array('Content-Type' => 'application/x-www-form-urlencoded'),
    );
    $endpoints = $this->getEndpoints();
    $response = drupal_http_request($endpoints['token'], $request_options);
    if (!isset($response->error) && $response->code == 200) {
      $response_data = drupal_json_decode($response->data);
      return array(
        'id_token' => $response_data['id_token'],
        'access_token' => $response_data['access_token'],
        'expire' => REQUEST_TIME + $response_data['expires_in'],
      );
    }
    else {
      openid_connect_log_request_error(__FUNCTION__, $this->name, $response);
      return FALSE;
    }
  }

  /**
   * Overrides OpenIDConnectClientBase::retrieveUserInfo().
   */
  public function retrieveUserInfo($access_token) {
    // Determine if we use Openid Userinfo or Graph API.
    switch ($this->getSetting('userinfo_graph_api_wa')) {
      case 1:
        $url = 'https://graph.windows.net/me?api-version=1.6';
        $upn = 'userPrincipalName';
        break;

      default:
        $endpoints = $this->getEndpoints();
        $url = $endpoints['userinfo'];
        $upn = 'upn';
        break;

    }

    // Perform the request.
    $options = array(
      'method' => 'GET',
      'headers' => array(
        'Content-Type' => 'application/json',
        'Authorization' => 'Bearer ' . $access_token,
      ),
    );
    $result = drupal_http_request($url, $options);

    if (in_array($result->code, array(200, 304))) {
      $userinfo = json_decode($result->data, TRUE);
    }
    else {
      drupal_set_message(t('The UserInfo cannot be retrieved. Please check your settings.'), 'error');

      return FALSE;
    }

    // If email is not there the user will not be created by Drupal, so we
    // add the principal name as email instead, so Drupal will create it anyway.
    if (!isset($userinfo['email'])) {
      drupal_set_message(t('Email address not found in UserInfo. Used username instead, please check.'), 'warning');

      $userinfo['email'] = $userinfo[$upn];
    }
    return $userinfo;
  }

}
