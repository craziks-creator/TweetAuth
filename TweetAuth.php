<?php

require 'OAuth.php';

class TweetAuth {
	private $oauthParams = array();
	private $OAuth;
	public $baseURL = 'https://api.twitter.com/1.1/';

	function __construct($consumerKey, $consumerSecret, $accessToken = null, $accessSecret = null) {
		$this->oauthParams = [
		'oauth_consumer_key' => $consumerKey,
		'oauth_nonce' => hash("sha1", time()),
		'oauth_signature_method' => 'HMAC-SHA1',
		'oauth_timestamp' => time(),
		'oauth_version' => '1.0'
		 ];

		 if($accessToken != null) {
		 	$this->oauthParams['oauth_token'] = $accessToken;
		 }

		 $this->OAuth = new OAuth($consumerKey, $consumerSecret, $accessToken, $accessSecret);
	}

	public function getRequestToken($callback) {
		$url = 'https://api.twitter.com/oauth/request_token';
		
		$requestParams = $this->oauthParams;
		$requestParams['oauth_callback'] = $callback;

		$baseString = $this->OAuth->buildBaseString("POST", $url, $requestParams);
		$requestParams['oauth_signature'] = $this->OAuth->buildSignature($baseString);

		$header = $this->OAuth->buildHeader($requestParams);
		
		$response = explode('&', $this->OAuth->executeRequest('POST', $url, $header));
		$requestToken = array();

		foreach($response as $r) {
			$r = explode('=', $r);
			$requestToken[$r[0]] = $r[1];
		}

		return $requestToken;
	}

	public function authenticateToken($requestToken) {
		return 'https://api.twitter.com/oauth/authenticate?oauth_token=' . $requestToken['oauth_token']; 
	}

	public function getAccessToken($oauthToken, $oauthVerifier) {
		$url = 'https://api.twitter.com/oauth/access_token';

		$requestParams = $this->oauthParams;
		$requestParams['oauth_token'] = $oauthToken;

		$baseString = $this->OAuth->buildBaseString("POST", $url, $requestParams);
		$requestParams['oauth_signature'] = $this->OAuth->buildSignature($baseString);
		$header = $this->OAuth->buildHeader($requestParams);
		$postFields = ['oauth_verifier' => $oauthVerifier];

		$response = $this->OAuth->executeRequest('POST', $url, $header, $postFields);

		$response = explode('&', $response);
		$accessToken = array();

		foreach($response as $r) {
			$r = explode('=', $r);
			$accessToken[$r[0]] = $r[1];
		}
	
		return $accessToken;
		
	}

	public function getRequest($endpoint, $getParams) {
		$url = $this->baseURL . $endpoint;
		$baseparams = array_merge($this->oauthParams, $getParams);

		ksort($baseparams);
		
		$baseString = $this->OAuth->buildBaseString("GET", $url, $baseparams);
		$this->oauthParams['oauth_signature'] = $signature = $this->OAuth->buildSignature($baseString);
		ksort($this->oauthParams);

		$header = $this->OAuth->buildHeader($this->oauthParams);
		
		return $this->OAuth->executeRequest("GET", $url, $header, null, $getParams);

	}

	public function postRequest($endpoint, $postParams) {
		$url = $this->baseURL . $endpoint;

		$baseparams = array_merge($this->oauthParams, $postParams);
		ksort($baseparams);

		$baseString = $this->OAuth->buildBaseString("POST", $url, $baseparams);
		$this->oauthParams['oauth_signature'] = $signature = $this->OAuth->buildSignature($baseString);
		ksort($this->oauthParams);

		$header = $this->OAuth->buildHeader($this->oauthParams);

		return $this->OAuth->executeRequest("POST", $url, $header, $postParams, NULL);

	}

}

?>