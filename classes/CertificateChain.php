<?php
require_once("Enum.php");
require_once("Certificate.php");
require_once("CertificateStore.php");

class CertVerifyResult extends Enum {
	const CERTVERIFY_EXPIRED=			"expired";
	const CERTVERIFY_NOT_VALID_YET=		"not valid yet";
	const CERTVERIFY_INVALID_KEYUSAGE=	"invalid keyUsage";
	const CERTVERIFY_INVALID_EXTKEYUSAGE=	"invalid extKeyUsage";
	const CERTVERIFY_INVALID_SIGNATURE=	"invalid signature";
	const CERTVERIFY_INVALID_CONSTRAINT="invalid constraints";
	const CERTVERIFY_ICOMPLETE_CHAIN=	"incomplete chain";
	const CERTVERIFY_UNTRUSTED_ROOT=	"untrusted root";
	const CERTVERIFY_UNSUPPORTED_SIGNATURE_ALGORITHM=	"unsupported signature algorithm";
}

class CertificateChain implements IteratorAggregate {

	var $chain;
	var $certStore;
	var $baseDate;
	var $endEntityKeyUsage;
	var $endEntityExtKeyUsage;

	function dumpChain($chain){
		foreach($chain as $idx=>$cert) {
			var_dump("#$idx:".$cert['cert']->getCommonName());
		}
	}
	
	function __construct($origin, $certStore, $options=NULL ) {
		$this->certStore = $certStore;

		if(!empty($options)) {
			if(isset($options["baseDate"]))
				$this->baseDate = $options["baseDate"];

			if(isset($options["endEntityKeyUsage"]))
				$this->endEntityKeyUsage = $options["endEntityKeyUsage"];

			if(isset($options["endEntityExtKeyUsage"]))
				$this->endEntityExtKeyUsage = $options["endEntityExtKeyUsage"];

		}
		
		$this->constructChain($origin);
	}
	
	public function getBaseDate($date) {
		return $this->baseDate;
	}
	
	public function getRoot() {
		foreach($this->chain as $idx=>$cert) {
			if($cert['cert']->isRoot() === true)
				return $cert;
		}
		return NULL;
	}
	
	public function getEndEntity() {
		foreach($this->chain as $idx=>$cert) {
			if($cert['depth'] === 0)
				return $cert;
		}
		return NULL;
	}
	
	public function count() {
		return sizeof($this->chain);
	}
	
	function getIterator() {
		return new ArrayIterator($this->chain);
	}
	
	public function isValidChain() {
		foreach($this->chain as $idx=>$cert) {
//			var_dump($cert['cert']->getCommonName());
//			var_dump($cert['validation']);
			if(!empty($cert['validation']))
				return false;
		}
		return true;
	}

	private function followChain( $targetCert ) {
		$chain[] = $targetCert;
		$issuerKeyID = ($targetCert['cert']->getAuthorityKeyIdentifier());

		if($issuerKeyID!==NULL) {
			$parentCert = $this->certStore->findByKeyID($issuerKeyID);
		} else {
			$parentCert = $this->certStore->findByDN($targetCert['cert']->getIssuerDN());
		}

		if($parentCert===NULL)
			return $chain;

		if($parentCert==$targetCert)
			return $chain;

		if(!$parentCert['cert']->isRoot()) {
			$chain = array_merge($chain,$this->followChain($parentCert));
		} else {
			$chain[] = $parentCert;
		}

		return $chain;
	}

	private function constructChain( $certTBV ) {
		
		if(!isset($certTBV['certificate'])||true) {
			$targetCert = $this->certStore->findBySignature($certTBV['certificate']['signature']);
			
			if(empty($targetCert))
				$targetCert = $this->certStore->findByDN($certTBV['certificate']['tbsCertificate']['subject']);
				
			if(empty($targetCert))
				throw new RuntimeException("Origin not found in store");
		} else {
			$targetCert['cert'] = new Certificate($certTBV);
			$targetCert['trusted'] = false;
		}
		
		$chain = $this->followChain($targetCert);
//		$this->dumpChain($chain);
		
		foreach($chain as $idx=>$cert) {
//			var_dump($cert['cert']);
//			var_dump($cert['cert']->getIssuerCommonName());

			$validateResult=[];

			if(isset($chain[$idx+1])) {
				$parent = ($chain[$idx+1]);
//				var_dump($parent['cert']->getCommonName());
				$cert['cert']->loadCA($parent['cert']->getRaw());
				try {
					if(!$cert['cert']->validateSignature())
						$validateResult[] = CertVerifyResult::CERTVERIFY_INVALID_SIGNATURE();
				} catch(phpseclib\Exception\UnsupportedAlgorithmException $e) {
					//throw new RuntimeException("SignatureAlgorithm not supported");
					$validateResult[] = CertVerifyResult::CERTVERIFY_UNSUPPORTED_SIGNATURE_ALGORITHM();
				}
			} else {
				if($cert['cert']->isRoot()) {
					$cert['cert']->loadCA($cert['cert']->getRaw());
					if(!$cert['cert']->validateSignature())
						$validateResult[] = CertVerifyResult::CERTVERIFY_INVALID_SIGNATURE();
					
					if($cert['trusted']===CertificateStore::STORE_UNTRUSTED)
						$validateResult[] = CertVerifyResult::CERTVERIFY_UNTRUSTED_ROOT();
				} else {
					$validateResult[] = CertVerifyResult::CERTVERIFY_ICOMPLETE_CHAIN();
				}
			}

			$cert['depth'] = $idx;
			$validateResult = array_merge($this->validateCertificate($cert),$validateResult);

			$cert['validation'] = array_unique($validateResult);
			$this->chain[$idx]=$cert;
//			$res[$certsIdx][] = $cert;
//			var_dump(array_keys($cert));
//			var_dump($cert['cert']->getCommonName());
//			var_dump($validateResult);
		}
//		$this->chain = array_reverse($this->chain);
	}

	// date and usage/constraints
	private function validateCertificate( $cert ) {
		$res = [];
		$validity = $cert['cert']->validateDate($this->baseDate);
		
		if(($validity==Certificate::CERTVALIDITY_NOT_VALID_YET))
			$res[] = CertVerifyResult::CERTVERIFY_NOT_VALID_YET();
		else if(($validity==Certificate::CERTVALIDITY_EXPIRED))
			$res[] = CertVerifyResult::CERTVERIFY_EXPIRED();
		
//		var_dump($cert['cert']->getExtension("id-ce-cRLDistributionPoints"));
		$keyusage = $cert['cert']->getExtension("id-ce-keyUsage");
		$extKeyusage = $cert['cert']->getExtension("id-ce-extKeyUsage");
		$basicConstraints = $cert['cert']->getExtension("id-ce-basicConstraints");

//		if(!empty($keyusage))var_dump($keyusage);
//		if(!empty($extKeyusage))var_dump($extKeyusage);
		
		if($cert['depth']!=0) {	// not leaf (==CA)
			if(!empty($keyusage))
			if(!in_array('keyCertSign',$keyusage["extnValue"]))
				$res[] = CertVerifyResult::CERTVERIFY_INVALID_KEYUSAGE();

			if(
				empty($basicConstraints)
				|| ($basicConstraints["critical"]!=true) 
				|| ($basicConstraints["extnValue"]["cA"]!=true)
			)
				$res[] = CertVerifyResult::CERTVERIFY_INVALID_CONSTRAINT();
		} else {	// leaf (==EndEntity)
			if(!empty($this->endEntityKeyUsage)) {
				if(!empty($this->endEntityKeyUsage['exactUsage'])) {
					if(!($this->_matchUsage($this->endEntityKeyUsage['exactUsage'],$keyusage['extnValue'],true)))
						$res[] = CertVerifyResult::CERTVERIFY_INVALID_KEYUSAGE();
				}

				if(!empty($this->endEntityKeyUsage['requireUsage'])) {
					if(!($this->_matchUsage($this->endEntityKeyUsage['requireUsage'],$keyusage['extnValue'],false)))
						$res[] = CertVerifyResult::CERTVERIFY_INVALID_KEYUSAGE();
				}
			}

			if(!empty($this->endEntityExtKeyUsage)) {
				if(!empty($this->endEntityExtKeyUsage['exactUsage'])) {
					if(!($this->_matchUsage($this->endEntityExtKeyUsage['exactUsage'],$extKeyusage['extnValue'],true)))
						$res[] = CertVerifyResult::CERTVERIFY_INVALID_EXTKEYUSAGE();
				}

				if(!empty($this->endEntityExtKeyUsage['requireUsage'])) {
					if(!($this->_matchUsage($this->endEntityExtKeyUsage['requireUsage'],$extKeyusage['extnValue'],false)))
						$res[] = CertVerifyResult::CERTVERIFY_INVALID_EXTKEYUSAGE();
				}
			}
		}
		return $res;
	}

	private function _matchUsage($constraints,$target,$exact=false) {
		if(empty($target))
			return false;

		sort($constraints);
		sort($target);
//		var_dump($constraints,$target);
		if($exact)
			return $constraints===$target;
		else {
			foreach($constraints as $usage) {
				if(!in_array($usage,$target))
					return false;
			}
			return true;
		}
	}
}

