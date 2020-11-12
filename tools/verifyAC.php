#!/usr/local/bin/php
<?php
require_once(__DIR__."/../vendor/autoload.php");
require_once(__DIR__."/../Authenticode.php");
require_once(__DIR__."/../classes/CertificateStore.php");
require_once(__DIR__."/../classes/termcolors.php");
require_once(__DIR__."/../classes/MicrosoftPe.php");

use phpseclib\File\X509;
	
	if(empty($argv[1]))
		die("usage: $argv[0] file\n");
		
	$filepath = $argv[1];
	$filename = basename($filepath);
	if(!file_exists($filepath))return;

	$acParser = new Authenticode($filepath);
	try {
		$valid = $acParser->isValid();
	} catch (Exception $e) {
//		var_dump(get_class($e));
//		var_dump($e->getMessage());
		$valid = false;
		addValidityResult($res,0,(eGray(eBold($filename))),$valid,["verified",$e->getMessage()]);
		emitResult($res);
		return;
	}

	{
		$indent=0;
//		addValidityResult($res,$indent,(eGray(eBold($filename)).": "),$valid,["OK","NG"]);
		addValidityResult($res,$indent,(eGray(eBold($filename))),$valid,["verified","not verified"]);

		foreach($acParser->getValidity() as $deridx=>$validities)

			foreach($validities as $idx=>$validity){
//				var_dump(($validity));
				$parsedInfo = $acParser->getParsedInfo()[$deridx][$idx];
//				var_dump(array_keys($parsedInfo["id-smime-ct-TSTInfo"]["validation"]));
				$indent++; {
					//addValidityResult($res,$indent,eGray(eBold("Authenticode #$idx:")),$validity["valid"]);
					addValidityResult($res,$indent,eGray(eUnderline("Authenticode #$idx:")),$validity["valid"]);
					$indent++; {
				
						addValidityResult($res,$indent,eGray(("Authenticode digest:")),$validity["Authenticode-digest"]);
						$indent++; {
							addStrResult($res,$indent,"Stored digest:",eYellow($parsedInfo["SpcIndirectData"]["validation"]["Authenticode-digest"]["storedDigest"]));
							addStrResult($res,$indent,"Calculated digest:",eYellow($parsedInfo["SpcIndirectData"]["validation"]["Authenticode-digest"]["calculatedDigest"]));
						} $indent--;
						addSeparator($res);

						addValidityResult($res,$indent,eGray(("SpcIndirectData:")),$validity["SpcIndirectData"]);
						$indent++; {
							addValidityResult($res,$indent,eGray(("SignedData digest:")),$parsedInfo["SpcIndirectData"]["validation"]["signedAttrs"]["valid"]);
							$indent++; {
								addStrResult($res,$indent,"Stored digest:",eYellow($parsedInfo["SpcIndirectData"]["validation"]["signedAttrs"]["storedDigest"]));
								addStrResult($res,$indent,"Calculated digest:",eYellow($parsedInfo["SpcIndirectData"]["validation"]["signedAttrs"]["calculatedDigest"]));
							} $indent--;
							
							addValidityResult($res,$indent,eGray(("SignedData signature:")),$parsedInfo["SpcIndirectData"]["validation"]["signature"]["valid"]);

							addValidityResult($res,$indent,eGray("Certificate Chain:"),$parsedInfo["SpcIndirectData"]["validation"]["certChain"]->isValidChain());
							$indent++; {
								emitCertChain($res,$indent,$parsedInfo["SpcIndirectData"]["validation"]["certChain"]);
							} $indent--;
						} $indent--;
						addSeparator($res);

if(isset($validity["countersignature-digest"])) {
						addValidityResult($res,$indent,eGray(("Countersignature:")),$validity["countersignature"]);
						
						$indent++; {
								addStrResult($res,$indent,eGray("Timestamp:"),eYellow(date("Y/m/d H:i:s",$parsedInfo["id-countersignature"]["timestamp"])));
								addValidityResult($res,$indent,eGray(("Signature digest:")),$parsedInfo["id-countersignature"]["validation"]["counterSignature"]["valid"]);
								$indent++; {
									addStrResult($res,$indent,"Stored digest:",eYellow($parsedInfo["id-countersignature"]["validation"]["counterSignature"]["storedDigest"]));
									addStrResult($res,$indent,"Calculated digest:",eYellow($parsedInfo["id-countersignature"]["validation"]["counterSignature"]["calculatedDigest"]));
								} $indent--;
								
								if($parsedInfo["id-countersignature"]["validation"]["signature"]["informal"])
									$msg=["OK, informal PKCS#1","NG, informal PKCS#1"];
								else
									$msg=["OK","NG"];
								addValidityResult($res,$indent,eGray(("Signature:")),$parsedInfo["id-countersignature"]["validation"]["signature"]["valid"],$msg);

								addValidityResult($res,$indent,eGray("Certificate Chain:"),$parsedInfo["id-countersignature"]["validation"]["certChain"]->isValidChain());
								$indent++; {
									emitCertChain($res,$indent,$parsedInfo["id-countersignature"]["validation"]["certChain"]);
								} $indent--;

						} $indent--;
}

if(isset($validity["TSTInfo-digest"])) {
						addValidityResult($res,$indent,eGray(("TSTInfo:")),$validity["TSTInfo"]);
						$indent++; {
							addStrResult($res,$indent,eGray("Timestamp:"),eYellow(date("Y/m/d H:i:s",$parsedInfo["id-smime-ct-TSTInfo"]["timestamp"])));
							addValidityResult($res,$indent,eGray(("TSTInfo digest:")),$parsedInfo["id-smime-ct-TSTInfo"]["validation"]["TSTInfo-digest"]["valid"]);
							$indent++; {
								addStrResult($res,$indent,"Stored digest:",eYellow($parsedInfo["id-smime-ct-TSTInfo"]["validation"]["TSTInfo-digest"]["storedDigest"]));
								addStrResult($res,$indent,"Calculated digest:",eYellow($parsedInfo["id-smime-ct-TSTInfo"]["validation"]["TSTInfo-digest"]["calculatedDigest"]));
							} $indent--;
							
							addValidityResult($res,$indent,eGray(("SignedData digest:")),$parsedInfo["id-smime-ct-TSTInfo"]["validation"]["signedAttrs"]["valid"]);
							$indent++; {
								addStrResult($res,$indent,"Stored digest:",eYellow($parsedInfo["id-smime-ct-TSTInfo"]["validation"]["signedAttrs"]["storedDigest"]));
								addStrResult($res,$indent,"Calculated digest:",eYellow($parsedInfo["id-smime-ct-TSTInfo"]["validation"]["signedAttrs"]["calculatedDigest"]));
							} $indent--;

								
							addValidityResult($res,$indent,eGray(("SignedData signature:")),$parsedInfo["id-smime-ct-TSTInfo"]["validation"]["signature"]["valid"]);
							addValidityResult($res,$indent,eGray("Certificate Chain:"),$parsedInfo["id-smime-ct-TSTInfo"]["validation"]["certChain"]->isValidChain());
							$indent++; {
								emitCertChain($res,$indent,$parsedInfo["id-smime-ct-TSTInfo"]["validation"]["certChain"]);
							} $indent--;
						} $indent--;
}

					} $indent--;
				} $indent--;
				addSeparator($res);
			}
		emitResult($res);
	}

	function emitCertChain(&$res,$indent,$chain) {
		foreach($chain as $idx=>$cert) {
			$msg = ["OK",implode(", ",$cert["validation"])];
			if(($idx+1)===$chain->count())
				$msg = ["trusted",implode(", ",$cert["validation"])];
			addValidityResult($res,$indent,eGreen("#$idx ".$cert['cert']->getCommonName()),count($cert["validation"])===0,$msg);
			
			$notBefore = date("Y/m/d H:i:s",strtotime($cert['cert']->getNotBefore()));
			$notAfter = date("Y/m/d H:i:s",strtotime($cert['cert']->getNotAfter()));
//			addStrResult($res,$indent+1,eGray("DN: ").eYellow((@$cert['cert']->getDN(X509::DN_STRING))),"");
			addStrResult($res,$indent+1,eGray("valid from ").eYellow($notBefore).eGray(" to ").eYellow($notAfter),"");
			addStrResult($res,$indent+1,eGray("keyid: ").eYellow(bin2hex($cert['cert']->getSubjectKeyIdentifier())),"");
			addStrResult($res,$indent+1,eGray("serial: ").eYellow($cert['cert']->getSerialNumber()),"");
			if(in_array(CertVerifyResult::CERTVERIFY_ICOMPLETE_CHAIN,$cert["validation"])){
				addValidityResult($res,$indent,ePurple("#".($idx+1)." ".$cert['cert']->getIssuerCommonName()),false,["valid",ePurple("missing")]);
				addStrResult($res,$indent+1,eGray("DN: ").eYellow(($cert['cert']->getIssuerDN(X509::DN_STRING))),"");
				addStrResult($res,$indent+1,eGray("keyid: ").eYellow(bin2hex($cert['cert']->getAuthorityKeyIdentifier())),"");
			}
		}

	}
	
	function emitResult($results) {
		$validityMax=0;
		$msgMax=0;
		$longest=0;
		foreach($results as $result) {
			$title = $result["title"];
			$msg = $result["msg"]??$result["validity"];
			$indent = (str_repeat("  ",$result["indent"]));
			
			$titleWidth = strlen(preg_replace("/\033\[[0-9]{1,2}m/","",$title));
			$msgWidth = strlen(preg_replace("/\033\[[0-9]{1,2}m/","",$msg));
			$indentWidth = strlen($indent);
			
			$lineWidth = $titleWidth+$msgWidth+$indentWidth;
			if($longest<$lineWidth)
				$longest=$lineWidth;
			if(isset($result["msg"]))
				if($msgMax<$lineWidth)
					$msgMax = $lineWidth;
			if(isset($result["validity"]))
				if($validityMax<$lineWidth)
					$validityMax = $lineWidth;
		}
		
		
		foreach($results as $result) {
			$title = $result["title"];
			if(isset($result["msg"])) {
				$msg = $result["msg"];
				$targetWidth = $msgMax;
			} else {
				$msg = $result["validity"];
				$targetWidth = $validityMax;
			}
			$targetWidth = $longest+4;
			$indent = (str_repeat("  ",$result["indent"]));
			
			$indentWidth = strlen($indent);
			$termWidth = $targetWidth;
			$titleWidth = strlen(preg_replace("/\033\[[0-9]{1,2}m/","",$title));
			$msgWidth = strlen(preg_replace("/\033\[[0-9]{1,2}m/","",$msg));
			$msgRawWidth = strlen($msg);
			
			$padding = $termWidth-($indentWidth+$titleWidth)+($msgRawWidth-$msgWidth);
			printf("%s%s%".$padding."s\n",$indent,$title,$msg);

		}
	}
	
	function addValidityResult(&$resArr,$indent,$title,$res,$msg=["OK","NG"]) {
		if($res)
			$result = ("[ ".eBold(eGreen($msg[0]))." ]");
		else
			$result = ("[ ".eBold(eRed($msg[1]))." ]");
	
		$resArr[] = ["title"=>$title,"validity"=>$result,"indent"=>$indent];
	}

	function addStrResult(&$resArr,$indent,$title,$msg) {
		$resArr[] = ["title"=>$title,"msg"=>$msg,"indent"=>$indent];
	}
	
	function addSeparator(&$resArr,$separator="") {
		$resArr[] = ["title"=>$separator,"msg"=>"","indent"=>NULL];
	}	
	
	function resultEmitter($level,$title,$res,$str=["valid","invalid"]) {
		if($res)
			$result = ("[ ".eBold(eGreen($str[0]))." ]");
		else
			$result = ("[ ".eBold(eRed($str[1]))." ]");
		
		return indent($level,$title,$result);

		$indent = (str_repeat("  ",$level));
		
		$indentWidth = strlen($indent);
		$termWidth = exec("tput cols");
		$titleWidth = strlen(preg_replace("/\033\[[0-9]{1,2}m/","",$title));


		$msgWidth = strlen(preg_replace("/\033\[[0-9]{1,2}m/","",$result));
		$msgRawWidth = strlen($result);
		
		$padding = $termWidth-($indentWidth+$titleWidth)+($msgRawWidth-$msgWidth);
		printf("%s%s%".$padding."s\n",$indent,$title,$result);
	}
	
	function indent($level,$title,$msg="") {
		$indent = (str_repeat("  ",$level));
		
		$indentWidth = strlen($indent);
		$termWidth = exec("tput cols");
		$titleWidth = strlen(preg_replace("/\033\[[0-9]{1,2}m/","",$title));
		$msgWidth = strlen(preg_replace("/\033\[[0-9]{1,2}m/","",$msg));
		$msgRawWidth = strlen($msg);
		
		$padding = $termWidth-($indentWidth+$titleWidth)+($msgRawWidth-$msgWidth);
		printf("%s%s%".$padding."s\n",$indent,$title,$msg);
	}
	
	
