<?php
use phpseclib\File\ASN1;
use phpseclib\File\X509;
use phpseclib\Crypt\RSA;
use phpseclib\Crypt\Hash;
use phpseclib\Math\BigInteger;


		$SpcUuid = array('type'=>ASN1::TYPE_OCTET_STRING);
		$SpcSerializedObject = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'classId' => $SpcUuid,
                'serializedData' => array('type'=>ASN1::TYPE_OCTET_STRING)
            )
        );

		$SpcString = array(
            'type' => ASN1::TYPE_CHOICE,
            'children' => array(
				'unicode' => [
							'constant' => 0,
							'implicit' => true,
							'type' => ASN1::TYPE_BMP_STRING
						 ],
				'ascii' => [
							'constant' => 1,
							'implicit' => true,
							'type' => ASN1::TYPE_IA5_STRING
						 ]
			)
		);
		
		$SpcLink = array(
            'type' => ASN1::TYPE_CHOICE,
            'children' => array(
				'url' => [
							'constant' => 0,
							'implicit' => true,
							'type' => ASN1::TYPE_IA5_STRING
						 ],
				'moniker' => [
							'constant' => 1,
							'implicit' => true,
						 ] + $SpcSerializedObject,
				'file' => [
							'constant' => 2,
							'explicit' => true,
						 ] + $SpcString,
            )
        );

		$SpcPeImageFlags = array(
            'type' => ASN1::TYPE_BIT_STRING,
            'mapping' => array(
				'includeResources',
				'includeDebugInfo',
				'includeImportAddressTable'
            ),
			'default' => 'includeResources'
        );

		$SpcPeImageData = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'flags' => $SpcPeImageFlags,
                'file' => $SpcLink
            )
        );

		$SpcAttributeTypeAndOptionalValue = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'type' => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
                'value' => array(
								'type'     => ASN1::TYPE_ANY,
//								'constant' => 0,
								'optional' => true,
								'explicit' => true,
								'children' => $SpcPeImageData
							)
            )
        );
		
		$SpcAlgorithmIdentifier = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'algorithm'  => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
                'parameters' => array(
                                    'type'     => ASN1::TYPE_ANY,
//									'constant' => 0,
									'explicit' => true,
                                    'optional' => true
                                )
            )
        );
		
		$digestInfo = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'digestAlgorithm' => $SpcAlgorithmIdentifier,
                'digest' => array(
                                  'type' => ASN1::TYPE_OCTET_STRING,
                              )
            )
        );
		
		$this->SpcIndirectDataContent = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'data' => $SpcAttributeTypeAndOptionalValue,
                'messageDigest' => $digestInfo
            )
        );
		
		$ContentInfo = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'contentType' => $ContentType,
                'content' => array(
                                  'type' => ASN1::TYPE_ANY,
                                  'constant' => 0,
                                  'optional' => true,
                                  'explicit' => true,
//								  'children' => $this->SpcIndirectDataContent
                              )
            )
        );

        $this->SignedDataAuthentiCode = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'version' => $CMSVersion,
                'digestAlgorithms' => $DigestAlgorithmIdentifiers,
                'contentInfo' => $ContentInfo,
                'certificates' => array(
                                     'constant' => 0,
                                     'optional' => true,
                                     'implicit' => true
                                 ) + $CertificateSet,
                'crls' => array(
                              'constant' => 1,
                              'optional' => true,
                              'implicit' => true
                          ) + $RevocationInfoChoices,
                'signerInfos' => $SignerInfos
            )
        );
