<?php
require_once("Certificate.php");

	class CertificateStore {
	
		var $certStore;
		const STORE_UNTRUSTED=0;
		const STORE_TRUSTED=1;
	
		function __construct() {
			$this->certStore = [];
		}
		
		function import( $in, $trusted=self::STORE_UNTRUSTED ) {
			$certs = $in;
			if(!is_array($certs))
				$certs = [$in];
			
			foreach($certs as $cert) {
				$newCert = new Certificate($cert);
				$uniq = (bin2hex($newCert->getSubjectKeyIdentifier()).$newCert->getCommonName());
				//var_dump($uniq);
				$newKey = hash("sha256",$uniq);
				if(empty($this->certStore[$newKey]))
					$this->certStore[$newKey] = ['cert'=>$newCert,'trusted'=>$trusted];
			}
			
		}
		
		function findBySerial($serial,$trusted=NULL) {
			foreach($this->certStore as $key=>$c) {
//				var_dump($serial==$c['cert']->getSerialNumber());
				if($serial==$c['cert']->getSerialNumber()) {
					if($trusted!==NULL){
						if($c['trusted']===$trusted)
							return $c['cert'];
					} else
						return $c;
				}
			}
			return NULL;
		}
		
		function findByKeyID($keyID,$trusted=NULL) {
			foreach($this->certStore as $key=>$c) {
//				var_dump($c['cert']);
				if($keyID==$c['cert']->getSubjectKeyIdentifier()) {
					if($trusted!==NULL){
						if($c['trusted']===$trusted)
							return $c['cert'];
					} else
						return $c;
				}
			}
			return NULL;
		}
		
		function findBySignature($signature,$trusted=NULL) {
			foreach($this->certStore as $key=>$c) {
//				var_dump($serial==$c['cert']->getSerialNumber());
				if($signature==$c['cert']->getSignature()) {
					if($trusted!==NULL){
						if($c['trusted']===$trusted)
							return $c['cert'];
					} else
						return $c;
				}
			}
			return NULL;
		}

		function _searchDN($rdnSeq,$type) {
//			var_dump($rdnSeq);
			foreach($rdnSeq as $d) {
//				var_dump($d);
				if($d[0]['type'] === $type)
					return $d[0];
			}
		}
		
		function findByDN($dn,$trusted=NULL) {
//			var_dump($dn);
			foreach($this->certStore as $key=>$c) {
				$match = true;
				foreach($dn['rdnSequence'] as $d) {
//					var_dump($d);
					$targetDN = $this->_searchDN($c['cert']->getDN()['rdnSequence'],$d[0]['type']);
					if($targetDN!==NULL) {
						$searchValue = array_values($d[0]['value'])[0];
						$targetValue = array_values($targetDN['value'])[0];
	//					var_dump($searchValue,$targetValue);
						$match = $match&&($searchValue===$targetValue);
					} else
						$match = false;
				}
				if($match)
					if($trusted!==NULL){
						if($c['trusted']===$trusted)
							return $c['cert'];
					} else
						return $c;
			}
			return NULL;
		}
		
		function dumpStore() {
			foreach($this->certStore as $key=>$c) {
				echo("$key: ".($c['trusted']?'trusted':'untrusted').":".$c['cert']->getCommonName());
				echo(" (".(bin2hex($c['cert']->getSubjectKeyIdentifier())).")");
				$isRoot = $c['cert']->isRoot();
				if($isRoot)
					echo(" [root]");
				else {
					$issuer = $c['cert']->getIssuerCommonName();
					echo(" by $issuer (".(bin2hex($c['cert']->getAuthorityKeyIdentifier())).")");
				}
				echo("\n");

			}
		}
	}
	
	
	
	
	