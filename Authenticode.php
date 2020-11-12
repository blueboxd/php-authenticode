<?php
//namespace Authenticode;

require_once(__DIR__."/vendor/autoload.php");
require_once(__DIR__."/classes/MicrosoftPe.php");

define("kCACerts",__DIR__."/trusted/cacerts/");
define("kTrustedRootCodeSigning",__DIR__."/trusted/codesigning/");
define("kTrustedRootTSA",__DIR__."/trusted/tsa/");

use phpseclib\File\CMS;
use phpseclib\File\X509;

require_once(__DIR__."/classes/Certificate.php");
require_once(__DIR__."/classes/CertificateStore.php");
require_once(__DIR__."/classes/CertificateChain.php");

class InvalidPEException extends \RuntimeException {}
class InvalidCertDirException extends \RuntimeException {}
class NoAuthenticodeException extends \RuntimeException {}
class InvalidAuthenticodeException extends \RuntimeException {}

class Authenticode implements IteratorAggregate {
	var $validity;
	var $wholeValidity;
	
	var $filepath;
	var $raw;
	
	var $kaitaiPE;
	var $cms;
	var $certificateStore;
	
	var $parsedInfo;

	function __construct($filepath) {
		$this->cms = NULL;
		$this->filepath = $filepath;
		$this->raw = file_get_contents($filepath);
		$this->certificateStore = NULL;
	}

	function getIterator() {
		return new ArrayIterator($this->parsedInfo);
	}

	public function isValid() {
		if(empty($this->cms))
			$this->validate();
		return $this->wholeValidity;
	}
	
	public function getValidity() {
		return $this->validity;
	}
	
	public function getValidationResults() {
		foreach($this->validity as $v) {
		
		}
	}

	public function getParsedInfo() {
		return $this->parsedInfo;
	}

	public function validate() {
		try {
			$this->kaitaiPE = Kaitai\Parser\MicrosoftPe::fromFile($this->filepath);
		} catch(Exception $e) {
			throw new InvalidPEException("invalid PE format");
		}

		$sections = $this->kaitaiPE->sections();

		$certDir = $this->kaitaiPE->optionalHdr()->dataDirs()->certificateTable();
		if($certDir->size()==0) {
			throw new NoAuthenticodeException("no Authenticode found");
		}
		
		$certPA = $certDir->virtualAddress();
		$certSize = $certDir->size();

		$DERs = $this->extractDERfromPE();
		if(empty($DERs)) {
			throw new InvalidCertDirException("certDir has invalid offset");
		}
		
		foreach($DERs as $derIdx=>$der) {
			$this->cms[$derIdx] = new CMS();

			if(!$this->cms[$derIdx]->load($der)) {
				throw new InvalidAuthenticodeException("failed to parse Authenticode");
			}
			
			if(empty($this->certificateStore)) {
				$this->certificateStore = new CertificateStore();
				//$this->certificateStore->import($this->_collectCerts(kCACerts),CertificateStore::STORE_TRUSTED);
				$this->certificateStore->import($this->_collectCerts(kTrustedRootCodeSigning),CertificateStore::STORE_TRUSTED);
			}
			$this->certificateStore->import($this->cms[$derIdx]->certs['raw'],CertificateStore::STORE_UNTRUSTED);

			$wholeValidity = true;
			foreach($this->cms[$derIdx]->currentCMS as $idx=>$authenticodeInfo)
			{
				$validity = [];
				$certsTBV = array();

				{
					$certToBeVerified = $authenticodeInfo['content']['validation']['signature']['signerInfo'];

					$this->parsedInfo[$derIdx][$idx]["SpcIndirectData"]['signerCertificate'] = $certToBeVerified;
					$this->parsedInfo[$derIdx][$idx]["SpcIndirectData"]['content'] = $authenticodeInfo['content']['contentInfo']['SpcIndirectDataContent'];
					$this->parsedInfo[$derIdx][$idx]["SpcIndirectData"]['validation'] = $authenticodeInfo['content']['validation'];

					foreach($authenticodeInfo['content']['signerInfos'] as $signerInfo) {
						if(isset($signerInfo['unsignedAttrs'])) {
							foreach($signerInfo['unsignedAttrs'] as $unsigedAttr) {

								if(isset($unsigedAttr['value']['content'])) {
									$title = $unsigedAttr['value']['content']['encapContentInfo']['eContentType'];

									$certToBeVerified = $unsigedAttr['value']['content']['validation']['signature']['signerInfo'];
									$this->parsedInfo[$derIdx][$idx][$title]['signerCertificate'] = $certToBeVerified;
									$this->parsedInfo[$derIdx][$idx][$title]['validation'] = $unsigedAttr['value']['content']['validation'];
//									var_dump($unsigedAttr['value']['content']['validation']);
									
									if($title=='id-smime-ct-TSTInfo') {
										$this->parsedInfo[$derIdx][$idx][$title]['content'] = $unsigedAttr['value']['content']['encapContentInfo']['TSTInfo'];
									}
								} else if(isset($unsigedAttr['type'])&&isset($unsigedAttr['value'])) {
									$title = $unsigedAttr['type'];

									if($title=='id-countersignature') {
										$certToBeVerified = $unsigedAttr['value']['validation']['signature']['signerInfo'];
										$this->parsedInfo[$derIdx][$idx][$title]['signerCertificate'] = $certToBeVerified;
										$this->parsedInfo[$derIdx][$idx][$title]['content'] = $unsigedAttr['value'];
										$this->parsedInfo[$derIdx][$idx][$title]['validation'] = $unsigedAttr['value']['validation'];
									}
								}
							}
						}
					}
				}
				
				/////////////////////////////////////////

				$baseDate =  new DateTime(null, new DateTimeZone(@date_default_timezone_get()));
				//var_dump($baseDate);
				foreach($this->parsedInfo[$derIdx][$idx] as $key=>&$info) {

					switch($key) {
						case 'SpcIndirectData':
							$digestAlgo = preg_replace('#^id-#', '', $info['content']["messageDigest"]["digestAlgorithm"]["algorithm"]);
							$digest = bin2hex($info['content']["messageDigest"]["digest"]);
							$targetRange = $this->extractBytesForAuthenticodeDigest();
							$hash = hash($digestAlgo,$targetRange);

							$matched = ($hash==$digest);
							$validity['SpcIndirectData-signedData'] = $info['validation']['valid'];
							$validity['Authenticode-digest'] = ($matched);
							$info['validation']['Authenticode-digest']['valid'] = ($matched);
							$info['validation']['Authenticode-digest']['digestAlgorithm'] = $digestAlgo;
							$info['validation']['Authenticode-digest']['storedDigest'] = $digest;
							$info['validation']['Authenticode-digest']['calculatedDigest'] = $hash;
						break;

						case 'id-smime-ct-TSTInfo':
							$validity['TSTInfo-signedData'] = $info['validation']['valid'];
							$validity['TSTInfo-digest'] = $info['content']['validation']['valid'];
							
							$baseDate = new DateTime($info['content']['genTime']);
							$certChain = new CertificateChain($info['signerCertificate'],$this->certificateStore,["baseDate"=>$baseDate,"endEntityExtKeyUsage"=>["requireUsage"=>["id-kp-timeStamping"]]]);
							$info['validation']['certChain'] = $certChain;
							$info['validation']['TSTInfo-digest'] = $info['content']['validation'];
							$info['timestamp'] = $baseDate->getTimestamp();
							$validity['TSTInfo-certChain'] = $certChain->isValidChain();
							$validity['TSTInfo'] = $validity['TSTInfo-signedData']&&$validity['TSTInfo-digest']&&$validity['TSTInfo-certChain'];
						break;

						case 'id-countersignature':
							$validity['countersignature-digest'] = $info['validation']['valid'];
							
							$signingTime = array_values(($this->_getSigningTime($info['content']['signedAttrs']))[0])[0];
							if(!empty($signingTime))
								$baseDate = new DateTime($signingTime);
							$info['timestamp'] = $baseDate->getTimestamp();
							$certChain = new CertificateChain($info['signerCertificate'],$this->certificateStore,["baseDate"=>$baseDate,"endEntityExtKeyUsage"=>["requireUsage"=>["id-kp-timeStamping"]]]);
							$info['validation']['certChain'] = $certChain;
							$validity['countersignature-certChain'] = $certChain->isValidChain();
							$validity['countersignature'] = $validity['countersignature-digest']&&$validity['countersignature-certChain'];
						break;
					}
				}

				$masterSignerChain = new CertificateChain($this->parsedInfo[$derIdx][$idx]["SpcIndirectData"]['signerCertificate'],$this->certificateStore,["baseDate"=>$baseDate,/*"endEntityKeyUsage"=>["exactUsage"=>["digitalSignature"]],*/"endEntityExtKeyUsage"=>["requireUsage"=>["id-kp-codeSigning"]]]);
				$validity['SpcIndirectData-certChain'] = $masterSignerChain->isValidChain();
				$validity['SpcIndirectData'] = $validity['SpcIndirectData-signedData']&&$validity['SpcIndirectData-certChain'];
				$codesigningCert = $masterSignerChain->getEndEntity();
				$this->parsedInfo[$derIdx][$idx]["SpcIndirectData"]['validation']['certChain'] = $masterSignerChain;

				//$wholeValidity = $wholeValidity&&$validity;
				//$this->validity[$idx] = $validity;

//				var_dump($validity);
				$totalValidity = true;
				foreach($validity as $name=>$valid) {
//					var_dump($name,$valid);
					$wholeValidity = $wholeValidity&&$valid;
					$totalValidity = $totalValidity&&$valid;
				}
				$validity["valid"] = $totalValidity;
				$this->validity[$derIdx][$idx] = $validity;
			}
			$this->wholeValidity = $wholeValidity;
		}
		
		if(0)
		foreach($this->parsedInfo as $parsedInfos)
		foreach($parsedInfos as $parsedInfo){
			//var_dump($parsedInfo);
			foreach($parsedInfo as $name=>$curinfo) {
				echo("$name:");
				foreach(($curinfo['validation']) as $subj=>$validationResult) {
					if($subj=="signature")continue;
					if($subj=="certChain")continue;
					echo("$subj:");var_dump($validationResult);
				}
			}
		}
		
		return $this;
	}
	
	private function _getSigningTime($attrs) {
		foreach($attrs as $attr)
		if($attr['type']=='id-signingTime')
			return $attr['value'];
		return NULL;
	}

	private function extractDERfromPE() {
		$certDir = $this->kaitaiPE->optionalHdr()->dataDirs()->certificateTable();
		$certPA = $certDir->virtualAddress();
		$certSize = $certDir->size();
		$rawsize = strlen($this->raw);
		
		if($certPA+$certSize>$rawsize)
			return NULL;

		$DERs = array();
		$pos = 0;
		while($pos < $certSize) {
			$certLen = unpack("V",substr($this->raw,$certPA+$pos,4))[1];
			$certRev = unpack("n",substr($this->raw,$certPA+$pos+4,2))[1];
			$certType = unpack("n",substr($this->raw,$certPA+$pos+6,2))[1];
			$DERs[] = (substr($this->raw,$certPA+$pos+8,$certLen-8));
			if($certLen%8)
				$certLen += (8- ($certLen%8));
			$pos += $certLen;
		}
		return $DERs;
	}
	
	private function _applyRange( $data, &$start, $size ) {
		$hashBody = substr($data,$start,$size);
		$range = substr($data,$start,$size);
		$start += $size;
		return $range;
	}

	private function extractBytesForAuthenticodeDigest() {
		$physicalSize = strlen($this->raw);
		
		$certDir = $this->kaitaiPE->optionalHdr()->dataDirs()->certificateTable();
		$certPA = $certDir->virtualAddress();
		$certSize = $certDir->size();

		$IMAGE_DOS_HEADER_size = $this->kaitaiPE->mz1()->headerSize();
		$dataDirectories = $this->kaitaiPE->optionalHdr()->windows()->numberOfRvaAndSizes();
		$isPE32plus = $this->kaitaiPE->optionalHdr()->std()->format()==\Kaitai\Parser\MicrosoftPe\PeFormat::PE32_PLUS;
		
		$IMAGE_NT_HEADER_Signature_size = 4;
		$IMAGE_FILE_HEADER_size = 20;
		$IMAGE_OPTIONAL_HEADER32_TillChecksum_size = 64;
		$IMAGE_OPTIONAL_HEADER32_Remaining_size = 28;
		if($isPE32plus)
			$IMAGE_OPTIONAL_HEADER32_Remaining_size += 16;
		
		$IMAGE_DATA_DIRECTORY_size = 8;
		$IMAGE_OPTIONAL_HEADER32_TillCertTable_size = ($IMAGE_DATA_DIRECTORY_size*4);
		$IMAGE_OPTIONAL_HEADER32_RemainingDir_size = ($IMAGE_DATA_DIRECTORY_size*($dataDirectories-(1+4)));
		
		$cursor = 0;
				
		$rangeSize = $IMAGE_DOS_HEADER_size + $IMAGE_NT_HEADER_Signature_size + $IMAGE_FILE_HEADER_size + $IMAGE_OPTIONAL_HEADER32_TillChecksum_size ;
		$targetRange = $this->_applyRange($this->raw,$cursor,$rangeSize);
		$cursor += 4;

		$rangeSize = $IMAGE_OPTIONAL_HEADER32_Remaining_size + $IMAGE_OPTIONAL_HEADER32_TillCertTable_size;
		$targetRange .= $this->_applyRange($this->raw,$cursor,$rangeSize);
		$cursor += $IMAGE_DATA_DIRECTORY_size;
		
		if(($certPA+$certSize) >= $physicalSize) {
			$rangeSize = ($physicalSize-$certSize)-$cursor;
			$targetRange .= $this->_applyRange($this->raw,$cursor,$rangeSize);
		} else {
			throw new InvalidArgumentException("cert table is not end of PE.\n");
		}
		
		return $targetRange;
	}
	
	private function _collectCerts($dir) {
		$certFiles = glob($dir."/*");
		$res = array();
		
		foreach($certFiles as $file) {
			$raw = file_get_contents($file);
//			$x509 = new X509();
//			if(!empty($x509->loadX509($raw)))
				$res[] = $raw;
		}
		return $res;
	}

}

