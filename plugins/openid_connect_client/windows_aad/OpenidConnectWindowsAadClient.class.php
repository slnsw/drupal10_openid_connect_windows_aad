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
   * Overrides OpenIDConnectClientBase::retrieveUserInfo().
   */
  public function retrieveUserInfo($access_token) {
    $endpoints = $this->getEndpoints();
    $url = $endpoints['userinfo'];
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
      drupal_set_message(t('The UserInfo cannot be retrieved. Please check if a proper url was used.'), 'error');

      return FALSE;
    }

    // If email is not there the user will not be created by Drupal, so we
    // add the username as email instead, so Drupal will create it anyway.
    if (!isset($userinfo['email'])) {
      $userinfo['email'] = $userinfo['upn'];
    }

    return $userinfo;
  }

}
