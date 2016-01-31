<?php

class OAuth {

	private $consumerKey;
	private $consumerSecret;

	private $accessToken;
	private $accessSecret;

	private $signingKey;

	function __construct($consumerKey, $consumerSecret, $accessToken = null, $accessSecret = null) {
		$this->consumerKey = $consumerKey;
		$this->consumerSecret = $consumerSecret;
		$this->accessToken = $accessToken;
		$this->accessSecret = $accessSecret;

		if($accessSecret == null) {
			$this->signingKey = rawurlencode($consumerSecret) . '&';
		}

		else {
			$this->signingKey = rawurlencode($consumerSecret) . '&' . rawurlencode($accessSecret);
		}
	}

	public function buildBaseString($method, $url, $params) {
		$stringParams = array();
		ksort($params);

		foreach($params as $key => $value) {
			$stringParams[] = rawurlencode($key) . '=' . rawurlencode($value);
		}

		return strtoupper($method) . '&' . rawurlencode($url) . '&' . rawurlencode(implode('&', $stringParams));
	}

	public function buildSignature($baseString) {
		return base64_encode(hash_hmac("sha1", $baseString, $this->signingKey, true));
	}

	public function buildHeader($params) {
		$header = 'Authorization: OAuth ';
		$headerParams = array();
		ksort($params);

		foreach($params as $key => $value) {
			$headerParams[] = rawurlencode($key) . '=' . rawurlencode($value);
		}

		$header .= implode(',', $headerParams);

		return array($header);
	}

	public function executeRequest($method, $url, $header, $postFields = null, $getFields = null) {
		if($getFields != null) {
			$fields = array();
			foreach($getFields as $key => $value) {
				$fields[] = rawurlencode($key) . '=' . rawurlencode($value);
			}
			$url .= '?' . implode('&', $fields);
		}
		
		$ch = curl_init($url);

		curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
		curl_setopt($ch, CURLOPT_HEADER, false);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

		if($method == 'POST') {
			curl_setopt($ch, CURLOPT_POST, true);
			if($postFields != null) {
				curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postFields));
			}
		}

		$response = curl_exec($ch);
		curl_close($ch);

		return $response;
	}
}

?>