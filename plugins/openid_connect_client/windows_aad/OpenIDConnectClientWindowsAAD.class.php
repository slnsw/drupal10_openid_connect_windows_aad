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
    // Windows Azure requires a separate request for userinfo, containing access
    // token in the header.
    $authorization = 'Authorization: Bearer ' . $access_token;
    $ch = curl_init($endpoints['userinfo']);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', $authorization));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $result = curl_exec($ch);
    $userinfo = json_decode($result, TRUE);

    // If email is not there the user will not be created by Drupal, so we
    // add the username as email instead, so Drupal will create it anyway.
    if (!isset($userinfo['email'])) {
      $userinfo['email'] = $userinfo['upn'];
    }

    return $userinfo;
  }

}
