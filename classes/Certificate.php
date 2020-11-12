<?php
require_once(__DIR__."/../vendor/autoload.php");
use phpseclib\File\X509;
use phpseclib\File\ASN1;
use phpseclib\File\ASN1\Maps;

	class Certificate extends X509 {
		private $raw;
	
		function __construct($cert=NULL) {
			parent::__construct();
			$this->raw = NULL;
			if($cert!==NULL) {
				if(is_array($cert)){
					if(isset($cert['certificate']))
						parent::loadX509($cert['certificate']);
					else if(isset($cert['tbsCertificate']))
						parent::loadX509($cert);
				} else {
					$this->raw = $cert;
					parent::loadX509($cert);
				}	
			}
			return $this;
		}
		
		function _stripKeyIdentifier($raw) {

			if(is_array($raw)) {
				if(isset($raw['keyIdentifier']))
					return $raw['keyIdentifier'];
			}

			$decoded = ASN1::decodeBER($raw);
			if(empty($decoded))
				return $raw;
//			var_dump($decoded);
			
			$parsed = ASN1::asn1map($decoded[0],Maps\AuthorityKeyIdentifier::MAP);
			if($parsed!==NULL) {
//				var_dump($parsed);
				if(isset($parsed['keyIdentifier']))
					return $parsed['keyIdentifier'];				
			}
			
			if($decoded[0]['type'] == ASN1::TYPE_SEQUENCE)			//AuthorityKeyIdentifier
				return $decoded[0]['content'][0]['content'];
			else if($decoded[0]['type'] == ASN1::TYPE_OCTET_STRING)	//SubjectKeyIdentifier
				return $decoded[0]['content'];

			return $raw;
		}

		function getKeyIdentifier($id) {
			$rawID = $this->getExtension($id)["extnValue"];
//			if(is_array($rawID))
//			var_dump($this->getCommonName());
//			var_dump(($rawID));
			if($rawID!==false)
				return $this->_stripKeyIdentifier($rawID);
			
			return NULL;
		}
		
		function getAuthorityKeyIdentifier() {
			return $this->getKeyIdentifier("id-ce-authorityKeyIdentifier");
		}
		
		function getSubjectKeyIdentifier() {
			return $this->getKeyIdentifier("id-ce-subjectKeyIdentifier");
		}
		
		function getCommonName() {
			if(count($this->getDNProp('id-at-commonName'))==0) {
//				debug_print_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
				return $this->getDN(X509::DN_STRING);
			}
			return $this->getDNProp('id-at-commonName')[0];
		}

		function getIssuerCommonName() {
			if(count($this->getIssuerDNProp('id-at-commonName'))==0) {
//				debug_print_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
				return $this->getIssuerDN(X509::DN_STRING);
			}
			return $this->getIssuerDNProp('id-at-commonName')[0];
		}
		
		function getSerialNumber() {
			return $this->getCurrentCert()['tbsCertificate']['serialNumber']->toHex();
		}

		function getSignature() {
			return $this->getCurrentCert()['signature'];
		}
		
		function getNotBefore() {
			$notBefore = $this->getCurrentCert()['tbsCertificate']['validity']['notBefore'];
			$notBefore = isset($notBefore['generalTime']) ? $notBefore['generalTime'] : $notBefore['utcTime'];
			return $notBefore;
		}

		function getNotAfter() {
			$notAfter = $this->getCurrentCert()['tbsCertificate']['validity']['notAfter'];
			$notAfter = isset($notAfter['generalTime']) ? $notAfter['generalTime'] : $notAfter['utcTime'];
			return $notAfter;
		}
		
		function isRoot() {
//			debug_print_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
			if($this->getCommonName() === $this->getIssuerCommonName())
				if(($this->getAuthorityKeyIdentifier())!==NULL) {
					if($this->getAuthorityKeyIdentifier()===$this->getSubjectKeyIdentifier())
						return true;
				} else
					return true;
			return false;
		}
		
		function getRaw() {
			if($this->raw!==NULL)
				return $this->raw;
//			else
//				return $this->saveX509($this->getCurrentCert());
		}
		
		public function getExtension($id, $cert = null, $path=null)
		{
			return $this->getExtensionHelper($id, $cert, $path);
		}
		
		private function getExtensionHelper($id, $cert = null, $path = null)
		{
			$extensions = $this->extensions($cert, $path);

			if (!is_array($extensions)) {
				return false;
			}

			foreach ($extensions as $key => $value) {
				if ($value['extnId'] == $id) {
					return $value;
				}
			}

			return false;
		}
	
		const CERTVALIDITY_NOT_VALID_YET=-1;
		const CERTVALIDITY_VALID=0;
		const CERTVALIDITY_EXPIRED=1;
		public function validateDate($date = null)
		{
			if (!is_array($this->getCurrentCert()) || !isset($this->getCurrentCert()['tbsCertificate'])) {
				return false;
			}

			if (!isset($date)) {
				$date = new DateTime($date, new DateTimeZone(@date_default_timezone_get()));
			}

			$notBefore = $this->getCurrentCert()['tbsCertificate']['validity']['notBefore'];
			$notBefore = isset($notBefore['generalTime']) ? $notBefore['generalTime'] : $notBefore['utcTime'];

			$notAfter = $this->getCurrentCert()['tbsCertificate']['validity']['notAfter'];
			$notAfter = isset($notAfter['generalTime']) ? $notAfter['generalTime'] : $notAfter['utcTime'];

			switch (true) {
				case $date < new DateTime($notBefore, new DateTimeZone(@date_default_timezone_get())):
					return self::CERTVALIDITY_NOT_VALID_YET;
				case $date > new DateTime($notAfter, new DateTimeZone(@date_default_timezone_get())):
					return self::CERTVALIDITY_EXPIRED;
			}

			return self::CERTVALIDITY_VALID;
		}

	}
	
