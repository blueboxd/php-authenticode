<?php

//include_once('File/ASN1.php');
//include_once('File/X509.php');
//include_once('Crypt/RSA.php');

use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;

namespace phpseclib\File;

	function hex_dump($data, $newline="\n")
	{
		static $from = '';
		static $to = '';
		
		static $width = 16; # number of bytes per line
		
		static $pad = '.'; # padding for non-visible characters
		
		if ($from==='')
		{
			for ($i=0; $i<=0xFF; $i++)
			{
				$from .= chr($i);
				$to .= ($i >= 0x20 && $i <= 0x7E) ? chr($i) : $pad;
			}
		}
		
		$hex = str_split(bin2hex($data), $width*2);
		$chars = str_split(strtr($data, $from, $to), $width);
		
		$offset = 0;
		foreach ($hex as $i => $line)
		{
			echo sprintf('% 6d',$offset).' : '.implode(' ', str_split($line,2)) . ' [' . $chars[$i] . ']' . $newline;
			$offset += $width;
		}
	}


use phpseclib\File\ASN1;
use phpseclib\File\X509;
use phpseclib\Crypt\RSA;
use phpseclib\Crypt\Hash;
use phpseclib\Math\BigInteger;
use phpseclib\File\ASN1\Maps;

class CMS extends X509 // File_CMS_SignedData
{
    var $currentCMS;
    var $oids;

    var $ContentInfo;
    var $SignedData;
	var $SignedDataAuthentiCode;
	var $SpcIndirectDataContent;
	var $SignerInfo;

    var $SigningCertificate;
    var $SigningCertificateV2;

    var $signatureSubjects;
    var $certs;

    var $baseSignedData;
    var $baseSignedInfo;
    var $hash = 'sha256';
    var $keys;

    var $signingCerts;
    var $essSigningCerts;
	
	   var $Certificate;

    /**#@+
     * ASN.1 syntax for various extensions
     *
     * @access private
     */
    var $DirectoryString;
    var $PKCS9String;
    var $AttributeValue;
    var $Extensions;
    var $KeyUsage;
    var $ExtKeyUsageSyntax;
    var $BasicConstraints;
    var $KeyIdentifier;
    var $CRLDistributionPoints;
    var $AuthorityKeyIdentifier;
    var $CertificatePolicies;
    var $AuthorityInfoAccessSyntax;
    var $SubjectAltName;
    var $PrivateKeyUsagePeriod;
    var $IssuerAltName;
    var $PolicyMappings;
    var $NameConstraints;

    var $CPSuri;
    var $UserNotice;

    var $netscape_cert_type;
    var $netscape_comment;
    var $netscape_ca_policy_url;

    var $Name;
    var $RelativeDistinguishedName;
    var $CRLNumber;
    var $CRLReason;
    var $IssuingDistributionPoint;
    var $InvalidityDate;
    var $CertificateIssuer;
    var $HoldInstructionCode;
    var $SignedPublicKeyAndChallenge;
    /**#@-*/

    /**
     * ASN.1 syntax for Certificate Signing Requests (RFC2986)
     *
     * @var array
     * @access private
     */
    var $CertificationRequest;

    /**
     * ASN.1 syntax for Certificate Revocation Lists (RFC5280)
     *
     * @var array
     * @access private
     */
    var $CertificateList;

    /**
     * Distinguished Name
     *
     * @var array
     * @access private
     */
    var $dn;

    /**
     * Public key
     *
     * @var string
     * @access private
     */
    var $publicKey;

    /**
     * Private key
     *
     * @var string
     * @access private
     */
    var $privateKey;

    /**
     * Object identifiers for X.509 certificates
     *
     * @var array
     * @access private
     * @link http://en.wikipedia.org/wiki/Object_identifier
     */
//    var $oids;

    /**
     * The certificate authorities
     *
     * @var array
     * @access private
     */
    var $CAs;

    /**
     * The currently loaded certificate
     *
     * @var array
     * @access private
     */
    var $currentCert;

    /**
     * The signature subject
     *
     * There's no guarantee File_X509 is going to reencode an X.509 cert in the same way it was originally
     * encoded so we take save the portion of the original cert that the signature would have made for.
     *
     * @var string
     * @access private
     */
    var $signatureSubject;

    /**
     * Certificate Start Date
     *
     * @var string
     * @access private
     */
    var $startDate;

    /**
     * Certificate End Date
     *
     * @var string
     * @access private
     */
    var $endDate;

    /**
     * Serial Number
     *
     * @var string
     * @access private
     */
    var $serialNumber;

    /**
     * Key Identifier
     *
     * See {@link http://tools.ietf.org/html/rfc5280#section-4.2.1.1 RFC5280#section-4.2.1.1} and
     * {@link http://tools.ietf.org/html/rfc5280#section-4.2.1.2 RFC5280#section-4.2.1.2}.
     *
     * @var string
     * @access private
     */
    var $currentKeyIdentifier;

    /**
     * CA Flag
     *
     * @var bool
     * @access private
     */
    var $caFlag = false;

    /**
     * SPKAC Challenge
     *
     * @var string
     * @access private
     */
    var $challenge;


    function __construct()
    {
        parent::__construct();
		
		{
		        $this->DirectoryString = array(
            'type'     => ASN1::TYPE_CHOICE,
            'children' => array(
                'teletexString'   => array('type' => ASN1::TYPE_TELETEX_STRING),
                'printableString' => array('type' => ASN1::TYPE_PRINTABLE_STRING),
                'universalString' => array('type' => ASN1::TYPE_UNIVERSAL_STRING),
                'utf8String'      => array('type' => ASN1::TYPE_UTF8_STRING),
                'bmpString'       => array('type' => ASN1::TYPE_BMP_STRING)
            )
        );

        $this->PKCS9String = array(
            'type'     => ASN1::TYPE_CHOICE,
            'children' => array(
                'ia5String'       => array('type' => ASN1::TYPE_IA5_STRING),
                'directoryString' => $this->DirectoryString
            )
        );

        $this->AttributeValue = array('type' => ASN1::TYPE_ANY);

        $AttributeType = array('type' => ASN1::TYPE_OBJECT_IDENTIFIER);

        $AttributeTypeAndValue = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'type' => $AttributeType,
                'value'=> $this->AttributeValue
            )
        );

        /*
        In practice, RDNs containing multiple name-value pairs (called "multivalued RDNs") are rare,
        but they can be useful at times when either there is no unique attribute in the entry or you
        want to ensure that the entry's DN contains some useful identifying information.

        - https://www.opends.org/wiki/page/DefinitionRelativeDistinguishedName
        */
        $this->RelativeDistinguishedName = array(
            'type'     => ASN1::TYPE_SET,
            'min'      => 1,
            'max'      => -1,
            'children' => $AttributeTypeAndValue
        );

        // http://tools.ietf.org/html/rfc5280#section-4.1.2.4
        $RDNSequence = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            // RDNSequence does not define a min or a max, which means it doesn't have one
            'min'      => 0,
            'max'      => -1,
            'children' => $this->RelativeDistinguishedName
        );

        $this->Name = array(
            'type'     => ASN1::TYPE_CHOICE,
            'children' => array(
                'rdnSequence' => $RDNSequence
            )
        );

        // http://tools.ietf.org/html/rfc5280#section-4.1.1.2
        $AlgorithmIdentifier = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'algorithm'  => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
                'parameters' => array(
                                    'type'     => ASN1::TYPE_ANY,
                                    'optional' => true
                                )
            )
        );

        /*
           A certificate using system MUST reject the certificate if it encounters
           a critical extension it does not recognize; however, a non-critical
           extension may be ignored if it is not recognized.

           http://tools.ietf.org/html/rfc5280#section-4.2
        */
        $Extension = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'extnId'   => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
                'critical' => array(
                                  'type'     => ASN1::TYPE_BOOLEAN,
                                  'optional' => true,
                                  'default'  => false
                              ),
                'extnValue' => array('type' => ASN1::TYPE_OCTET_STRING)
            )
        );

        $this->Extensions = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            // technically, it's MAX, but we'll assume anything < 0 is MAX
            'max'      => -1,
            // if 'children' isn't an array then 'min' and 'max' must be defined
            'children' => $Extension
        );

        $SubjectPublicKeyInfo = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'algorithm'        => $AlgorithmIdentifier,
                'subjectPublicKey' => array('type' => ASN1::TYPE_BIT_STRING)
            )
        );

        $UniqueIdentifier = array('type' => ASN1::TYPE_BIT_STRING);

        $Time = array(
            'type'     => ASN1::TYPE_CHOICE,
            'children' => array(
                'utcTime'     => array('type' => ASN1::TYPE_UTC_TIME),
                'generalTime' => array('type' => ASN1::TYPE_GENERALIZED_TIME)
            )
        );

        // http://tools.ietf.org/html/rfc5280#section-4.1.2.5
        $Validity = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'notBefore' => $Time,
                'notAfter'  => $Time
            )
        );

        $CertificateSerialNumber = array('type' => ASN1::TYPE_INTEGER);

        $Version = array(
            'type'    => ASN1::TYPE_INTEGER,
//            'mapping' => array('v1', 'v2', 'v3')
        );

        // assert($TBSCertificate['children']['signature'] == $Certificate['children']['signatureAlgorithm'])
        $TBSCertificate = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                // technically, default implies optional, but we'll define it as being optional, none-the-less, just to
                // reenforce that fact
                'version'             => array(
                                             'constant' => 0,
                                             'optional' => true,
                                             'explicit' => true,
                                             'default'  => '1'
                                         ) + $Version,
                'serialNumber'         => $CertificateSerialNumber,
                'signature'            => $AlgorithmIdentifier,
                'issuer'               => $this->Name,
                'validity'             => $Validity,
                'subject'              => $this->Name,
                'subjectPublicKeyInfo' => $SubjectPublicKeyInfo,
                // implicit means that the T in the TLV structure is to be rewritten, regardless of the type
                'issuerUniqueID'       => array(
                                               'constant' => 1,
                                               'optional' => true,
                                               'implicit' => true
                                           ) + $UniqueIdentifier,
                'subjectUniqueID'       => array(
                                               'constant' => 2,
                                               'optional' => true,
                                               'implicit' => true
                                           ) + $UniqueIdentifier,
                // <http://tools.ietf.org/html/rfc2459#page-74> doesn't use the EXPLICIT keyword but if
                // it's not IMPLICIT, it's EXPLICIT
                'extensions'            => array(
                                               'constant' => 3,
                                               'optional' => true,
                                               'explicit' => true
                                           ) + $this->Extensions
            )
        );

        $this->Certificate = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                 'tbsCertificate'     => $TBSCertificate,
                 'signatureAlgorithm' => $AlgorithmIdentifier,
                 'signature'          => array('type' => ASN1::TYPE_BIT_STRING)
            )
        );

        $this->KeyUsage = array(
            'type'    => ASN1::TYPE_BIT_STRING,
            'mapping' => array(
                'digitalSignature',
                'nonRepudiation',
                'keyEncipherment',
                'dataEncipherment',
                'keyAgreement',
                'keyCertSign',
                'cRLSign',
                'encipherOnly',
                'decipherOnly'
            )
        );

        $this->BasicConstraints = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'cA'                => array(
                                                 'type'     => ASN1::TYPE_BOOLEAN,
                                                 'optional' => true,
                                                 'default'  => false
                                       ),
                'pathLenConstraint' => array(
                                                 'type' => ASN1::TYPE_INTEGER,
                                                 'optional' => true
                                       )
            )
        );

        $this->KeyIdentifier = array('type' => ASN1::TYPE_OCTET_STRING);

        $OrganizationalUnitNames = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => 4, // ub-organizational-units
            'children' => array('type' => ASN1::TYPE_PRINTABLE_STRING)
        );

        $PersonalName = array(
            'type'     => ASN1::TYPE_SET,
            'children' => array(
                'surname'              => array(
                                           'type' => ASN1::TYPE_PRINTABLE_STRING,
                                           'constant' => 0,
                                           'optional' => true,
                                           'implicit' => true
                                         ),
                'given-name'           => array(
                                           'type' => ASN1::TYPE_PRINTABLE_STRING,
                                           'constant' => 1,
                                           'optional' => true,
                                           'implicit' => true
                                         ),
                'initials'             => array(
                                           'type' => ASN1::TYPE_PRINTABLE_STRING,
                                           'constant' => 2,
                                           'optional' => true,
                                           'implicit' => true
                                         ),
                'generation-qualifier' => array(
                                           'type' => ASN1::TYPE_PRINTABLE_STRING,
                                           'constant' => 3,
                                           'optional' => true,
                                           'implicit' => true
                                         )
            )
        );

        $NumericUserIdentifier = array('type' => ASN1::TYPE_NUMERIC_STRING);

        $OrganizationName = array('type' => ASN1::TYPE_PRINTABLE_STRING);

        $PrivateDomainName = array(
            'type'     => ASN1::TYPE_CHOICE,
            'children' => array(
                'numeric'   => array('type' => ASN1::TYPE_NUMERIC_STRING),
                'printable' => array('type' => ASN1::TYPE_PRINTABLE_STRING)
            )
        );

        $TerminalIdentifier = array('type' => ASN1::TYPE_PRINTABLE_STRING);

        $NetworkAddress = array('type' => ASN1::TYPE_NUMERIC_STRING);

        $AdministrationDomainName = array(
            'type'     => ASN1::TYPE_CHOICE,
            // if class isn't present it's assumed to be ASN1::CLASS_UNIVERSAL or
            // (if constant is present) ASN1::CLASS_CONTEXT_SPECIFIC
            'class'    => ASN1::CLASS_APPLICATION,
            'cast'     => 2,
            'children' => array(
                'numeric'   => array('type' => ASN1::TYPE_NUMERIC_STRING),
                'printable' => array('type' => ASN1::TYPE_PRINTABLE_STRING)
            )
        );

        $CountryName = array(
            'type'     => ASN1::TYPE_CHOICE,
            // if class isn't present it's assumed to be ASN1::CLASS_UNIVERSAL or
            // (if constant is present) ASN1::CLASS_CONTEXT_SPECIFIC
            'class'    => ASN1::CLASS_APPLICATION,
            'cast'     => 1,
            'children' => array(
                'x121-dcc-code'        => array('type' => ASN1::TYPE_NUMERIC_STRING),
                'iso-3166-alpha2-code' => array('type' => ASN1::TYPE_PRINTABLE_STRING)
            )
        );

        $AnotherName = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                 'type-id' => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
                 'value'   => array(
                                  'type' => ASN1::TYPE_ANY,
                                  'constant' => 0,
                                  'optional' => true,
                                  'explicit' => true
                              )
            )
        );

        $ExtensionAttribute = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                 'extension-attribute-type'  => array(
                                                    'type' => ASN1::TYPE_PRINTABLE_STRING,
                                                    'constant' => 0,
                                                    'optional' => true,
                                                    'implicit' => true
                                                ),
                 'extension-attribute-value' => array(
                                                    'type' => ASN1::TYPE_ANY,
                                                    'constant' => 1,
                                                    'optional' => true,
                                                    'explicit' => true
                                                )
            )
        );

        $ExtensionAttributes = array(
            'type'     => ASN1::TYPE_SET,
            'min'      => 1,
            'max'      => 256, // ub-extension-attributes
            'children' => $ExtensionAttribute
        );

        $BuiltInDomainDefinedAttribute = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                 'type'  => array('type' => ASN1::TYPE_PRINTABLE_STRING),
                 'value' => array('type' => ASN1::TYPE_PRINTABLE_STRING)
            )
        );

        $BuiltInDomainDefinedAttributes = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => 4, // ub-domain-defined-attributes
            'children' => $BuiltInDomainDefinedAttribute
        );

        $BuiltInStandardAttributes =  array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'country-name'               => array('optional' => true) + $CountryName,
                'administration-domain-name' => array('optional' => true) + $AdministrationDomainName,
                'network-address'            => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $NetworkAddress,
                'terminal-identifier'        => array(
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $TerminalIdentifier,
                'private-domain-name'        => array(
                                                 'constant' => 2,
                                                 'optional' => true,
                                                 'explicit' => true
                                               ) + $PrivateDomainName,
                'organization-name'          => array(
                                                 'constant' => 3,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $OrganizationName,
                'numeric-user-identifier'    => array(
                                                 'constant' => 4,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $NumericUserIdentifier,
                'personal-name'              => array(
                                                 'constant' => 5,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $PersonalName,
                'organizational-unit-names'  => array(
                                                 'constant' => 6,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $OrganizationalUnitNames
            )
        );

        $ORAddress = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                 'built-in-standard-attributes'       => $BuiltInStandardAttributes,
                 'built-in-domain-defined-attributes' => array('optional' => true) + $BuiltInDomainDefinedAttributes,
                 'extension-attributes'               => array('optional' => true) + $ExtensionAttributes
            )
        );

        $EDIPartyName = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                 'nameAssigner' => array(
                                    'constant' => 0,
                                    'optional' => true,
                                    'implicit' => true
                                ) + $this->DirectoryString,
                 // partyName is technically required but File_ASN1 doesn't currently support non-optional constants and
                 // setting it to optional gets the job done in any event.
                 'partyName'    => array(
                                    'constant' => 1,
                                    'optional' => true,
                                    'implicit' => true
                                ) + $this->DirectoryString
            )
        );

        $GeneralName = array(
            'type'     => ASN1::TYPE_CHOICE,
            'children' => array(
                'otherName'                 => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $AnotherName,
                'rfc822Name'                => array(
                                                 'type' => ASN1::TYPE_IA5_STRING,
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'dNSName'                   => array(
                                                 'type' => ASN1::TYPE_IA5_STRING,
                                                 'constant' => 2,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'x400Address'               => array(
                                                 'constant' => 3,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $ORAddress,
                'directoryName'             => array(
                                                 'constant' => 4,
                                                 'optional' => true,
                                                 'explicit' => true
                                               ) + $this->Name,
                'ediPartyName'              => array(
                                                 'constant' => 5,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $EDIPartyName,
                'uniformResourceIdentifier' => array(
                                                 'type' => ASN1::TYPE_IA5_STRING,
                                                 'constant' => 6,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'iPAddress'                 => array(
                                                 'type' => ASN1::TYPE_OCTET_STRING,
                                                 'constant' => 7,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'registeredID'              => array(
                                                 'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                                                 'constant' => 8,
                                                 'optional' => true,
                                                 'implicit' => true
                                               )
            )
        );

        $GeneralNames = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $GeneralName
        );

        $this->IssuerAltName = $GeneralNames;

        $ReasonFlags = array(
            'type'    => ASN1::TYPE_BIT_STRING,
            'mapping' => array(
                'unused',
                'keyCompromise',
                'cACompromise',
                'affiliationChanged',
                'superseded',
                'cessationOfOperation',
                'certificateHold',
                'privilegeWithdrawn',
                'aACompromise'
            )
        );

        $DistributionPointName = array(
            'type'     => ASN1::TYPE_CHOICE,
            'children' => array(
                'fullName'                => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true
                                       ) + $GeneralNames,
                'nameRelativeToCRLIssuer' => array(
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                       ) + $this->RelativeDistinguishedName
            )
        );

        $DistributionPoint = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'distributionPoint' => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'explicit' => true
                                       ) + $DistributionPointName,
                'reasons'           => array(
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                       ) + $ReasonFlags,
                'cRLIssuer'         => array(
                                                 'constant' => 2,
                                                 'optional' => true,
                                                 'implicit' => true
                                       ) + $GeneralNames
            )
        );

        $this->CRLDistributionPoints = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $DistributionPoint
        );

        $this->AuthorityKeyIdentifier = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'keyIdentifier'             => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $this->KeyIdentifier,
                'authorityCertIssuer'       => array(
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $GeneralNames,
                'authorityCertSerialNumber' => array(
                                                 'constant' => 2,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $CertificateSerialNumber
            )
        );

        $PolicyQualifierId = array('type' => ASN1::TYPE_OBJECT_IDENTIFIER);

        $PolicyQualifierInfo = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'policyQualifierId' => $PolicyQualifierId,
                'qualifier'         => array('type' => ASN1::TYPE_ANY)
            )
        );

        $CertPolicyId = array('type' => ASN1::TYPE_OBJECT_IDENTIFIER);

        $PolicyInformation = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'policyIdentifier' => $CertPolicyId,
                'policyQualifiers' => array(
                                          'type'     => ASN1::TYPE_SEQUENCE,
                                          'min'      => 0,
                                          'max'      => -1,
                                          'optional' => true,
                                          'children' => $PolicyQualifierInfo
                                      )
            )
        );

        $this->CertificatePolicies = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $PolicyInformation
        );

        $this->PolicyMappings = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => array(
                              'type'     => ASN1::TYPE_SEQUENCE,
                              'children' => array(
                                  'issuerDomainPolicy' => $CertPolicyId,
                                  'subjectDomainPolicy' => $CertPolicyId
                              )
                       )
        );

        $KeyPurposeId = array('type' => ASN1::TYPE_OBJECT_IDENTIFIER);

        $this->ExtKeyUsageSyntax = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $KeyPurposeId
        );

        $AccessDescription = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'accessMethod'   => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
                'accessLocation' => $GeneralName
            )
        );

        $this->AuthorityInfoAccessSyntax = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $AccessDescription
        );

        $this->SubjectAltName = $GeneralNames;

        $this->PrivateKeyUsagePeriod = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'notBefore' => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true,
                                                 'type' => ASN1::TYPE_GENERALIZED_TIME),
                'notAfter'  => array(
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true,
                                                 'type' => ASN1::TYPE_GENERALIZED_TIME)
            )
        );

        $BaseDistance = array('type' => ASN1::TYPE_INTEGER);

        $GeneralSubtree = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'base'    => $GeneralName,
                'minimum' => array(
                                 'constant' => 0,
                                 'optional' => true,
                                 'implicit' => true,
                                 'default' => new BigInteger(0)
                             ) + $BaseDistance,
                'maximum' => array(
                                 'constant' => 1,
                                 'optional' => true,
                                 'implicit' => true,
                             ) + $BaseDistance
            )
        );

        $GeneralSubtrees = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $GeneralSubtree
        );

        $this->NameConstraints = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'permittedSubtrees' => array(
                                           'constant' => 0,
                                           'optional' => true,
                                           'implicit' => true
                                       ) + $GeneralSubtrees,
                'excludedSubtrees'  => array(
                                           'constant' => 1,
                                           'optional' => true,
                                           'implicit' => true
                                       ) + $GeneralSubtrees
            )
        );

        $this->CPSuri = array('type' => ASN1::TYPE_IA5_STRING);

        $DisplayText = array(
            'type'     => ASN1::TYPE_CHOICE,
            'children' => array(
                'ia5String'     => array('type' => ASN1::TYPE_IA5_STRING),
                'visibleString' => array('type' => ASN1::TYPE_VISIBLE_STRING),
                'bmpString'     => array('type' => ASN1::TYPE_BMP_STRING),
                'utf8String'    => array('type' => ASN1::TYPE_UTF8_STRING)
            )
        );

        $NoticeReference = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'organization'  => $DisplayText,
                'noticeNumbers' => array(
                                       'type'     => ASN1::TYPE_SEQUENCE,
                                       'min'      => 1,
                                       'max'      => 200,
                                       'children' => array('type' => ASN1::TYPE_INTEGER)
                                   )
            )
        );

        $this->UserNotice = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'noticeRef' => array(
                                           'optional' => true,
                                           'implicit' => true
                                       ) + $NoticeReference,
                'explicitText'  => array(
                                           'optional' => true,
                                           'implicit' => true
                                       ) + $DisplayText
            )
        );

        // mapping is from <http://www.mozilla.org/projects/security/pki/nss/tech-notes/tn3.html>
        $this->netscape_cert_type = array(
            'type'    => ASN1::TYPE_BIT_STRING,
            'mapping' => array(
                'SSLClient',
                'SSLServer',
                'Email',
                'ObjectSigning',
                'Reserved',
                'SSLCA',
                'EmailCA',
                'ObjectSigningCA'
            )
        );

        $this->netscape_comment = array('type' => ASN1::TYPE_IA5_STRING);
        $this->netscape_ca_policy_url = array('type' => ASN1::TYPE_IA5_STRING);

        // attribute is used in RFC2986 but we're using the RFC5280 definition

        $Attribute = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'type' => $AttributeType,
                'value'=> array(
                              'type'     => ASN1::TYPE_SET,
                              'min'      => 1,
                              'max'      => -1,
                              'children' => $this->AttributeValue
                          )
            )
        );

        // adapted from <http://tools.ietf.org/html/rfc2986>

        $Attributes = array(
            'type'     => ASN1::TYPE_SET,
            'min'      => 1,
            'max'      => -1,
            'children' => $Attribute
        );

        $CertificationRequestInfo = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'version'       => array(
                                       'type' => ASN1::TYPE_INTEGER,
                                       'mapping' => array('v1')
                                   ),
                'subject'       => $this->Name,
                'subjectPKInfo' => $SubjectPublicKeyInfo,
                'attributes'    => array(
                                       'constant' => 0,
                                       'optional' => true,
                                       'implicit' => true
                                   ) + $Attributes,
            )
        );

        $this->CertificationRequest = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'certificationRequestInfo' => $CertificationRequestInfo,
                'signatureAlgorithm'       => $AlgorithmIdentifier,
                'signature'                => array('type' => ASN1::TYPE_BIT_STRING)
            )
        );

        $RevokedCertificate = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                              'userCertificate'    => $CertificateSerialNumber,
                              'revocationDate'     => $Time,
                              'crlEntryExtensions' => array(
                                                          'optional' => true
                                                      ) + $this->Extensions
                          )
        );

        $TBSCertList = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'version'             => array(
                                             'optional' => true,
                                             'default'  => 'v1'
                                         ) + $Version,
                'signature'           => $AlgorithmIdentifier,
                'issuer'              => $this->Name,
                'thisUpdate'          => $Time,
                'nextUpdate'          => array(
                                             'optional' => true
                                         ) + $Time,
                'revokedCertificates' => array(
                                             'type'     => ASN1::TYPE_SEQUENCE,
                                             'optional' => true,
                                             'min'      => 0,
                                             'max'      => -1,
                                             'children' => $RevokedCertificate
                                         ),
                'crlExtensions'       => array(
                                             'constant' => 0,
                                             'optional' => true,
                                             'explicit' => true
                                         ) + $this->Extensions
            )
        );

        $this->CertificateList = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'tbsCertList'        => $TBSCertList,
                'signatureAlgorithm' => $AlgorithmIdentifier,
                'signature'          => array('type' => ASN1::TYPE_BIT_STRING)
            )
        );

        $this->CRLNumber = array('type' => ASN1::TYPE_INTEGER);

        $this->CRLReason = array('type' => ASN1::TYPE_ENUMERATED,
           'mapping' => array(
                            'unspecified',
                            'keyCompromise',
                            'cACompromise',
                            'affiliationChanged',
                            'superseded',
                            'cessationOfOperation',
                            'certificateHold',
                            // Value 7 is not used.
                            8 => 'removeFromCRL',
                            'privilegeWithdrawn',
                            'aACompromise'
            )
        );

        $this->IssuingDistributionPoint = array('type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'distributionPoint'          => array(
                                                    'constant' => 0,
                                                    'optional' => true,
                                                    'explicit' => true
                                                ) + $DistributionPointName,
                'onlyContainsUserCerts'      => array(
                                                    'type'     => ASN1::TYPE_BOOLEAN,
                                                    'constant' => 1,
                                                    'optional' => true,
                                                    'default'  => false,
                                                    'implicit' => true
                                                ),
                'onlyContainsCACerts'        => array(
                                                    'type'     => ASN1::TYPE_BOOLEAN,
                                                    'constant' => 2,
                                                    'optional' => true,
                                                    'default'  => false,
                                                    'implicit' => true
                                                ),
                'onlySomeReasons'           => array(
                                                    'constant' => 3,
                                                    'optional' => true,
                                                    'implicit' => true
                                                ) + $ReasonFlags,
                'indirectCRL'               => array(
                                                    'type'     => ASN1::TYPE_BOOLEAN,
                                                    'constant' => 4,
                                                    'optional' => true,
                                                    'default'  => false,
                                                    'implicit' => true
                                                ),
                'onlyContainsAttributeCerts' => array(
                                                    'type'     => ASN1::TYPE_BOOLEAN,
                                                    'constant' => 5,
                                                    'optional' => true,
                                                    'default'  => false,
                                                    'implicit' => true
                                                )
                          )
        );

        $this->InvalidityDate = array('type' => ASN1::TYPE_GENERALIZED_TIME);

        $this->CertificateIssuer = $GeneralNames;

        $this->HoldInstructionCode = array('type' => ASN1::TYPE_OBJECT_IDENTIFIER);

        $PublicKeyAndChallenge = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'spki'      => $SubjectPublicKeyInfo,
                'challenge' => array('type' => ASN1::TYPE_IA5_STRING)
            )
        );

        $this->SignedPublicKeyAndChallenge = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'publicKeyAndChallenge' => $PublicKeyAndChallenge,
                'signatureAlgorithm'    => $AlgorithmIdentifier,
                'signature'             => array('type' => ASN1::TYPE_BIT_STRING)
            )
        );

        $this->SubjectDirectoryAttributes = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $Attribute
        );

        $QCStatement = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'statementId' => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
                'statementInfo' => array(
                    'type' => ASN1::TYPE_ANY,
                    'optional' => true
                )
            )
        );

        $this->QCStatements = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $QCStatement
        );
		
		// TSTInfo
		$messageImprint = array(
			'type' => ASN1::TYPE_SEQUENCE,
			'children' => [
				'hashAlgorithm' => $AlgorithmIdentifier,
				'hashedMessage' => ['type'=>ASN1::TYPE_OCTET_STRING]
			]
		);

		$accuracy = array(
			'type' => ASN1::TYPE_SEQUENCE,
			'optional'=>true,
			'children' => [
				'seconds' =>[	'type'=>ASN1::TYPE_INTEGER,
								'optional'=>true
							],
				'millis' => [	'type'=>ASN1::TYPE_INTEGER,
								'min'=>1,
								'max'=>999,
								'optional'=>true,
								'constant' => 0
							],
				'micros' => [	'type'=>ASN1::TYPE_INTEGER,
								'min'=>1,
								'max'=>999,
								'optional'=>true,
								'constant' => 1
							]
			]
		);
		
		/*
		TSTInfo ::= SEQUENCE { 
			version INTEGER { v1(1) }, 
			policy TSAPolicyId, 
			messageImprint MessageImprint, 
			serialNumber INTEGER, 
			genTime GeneralizedTime, 
			accuracy Accuracy OPTIONAL, 
			ordering BOOLEAN OPTIONAL DEFAULT FALSE, 
			nonce INTEGER OPTIONAL, 
			tsa [0] IMPLICIT GeneralNames OPTIONAL, 
			extensions [1] IMPLICIT Extensions OPTIONAL
		}
		*/
		
		$this->TSTInfo = array(
			   'type'		=> ASN1::TYPE_SEQUENCE,
			   'children'	=> [
				   'version'	=> [
						'type'	=> ASN1::TYPE_INTEGER,
					   'mapping'=> ['invalid','v1'],
					   'default'=> 'v1'
					],
				   'policy'			=> ['type'=>ASN1::TYPE_OBJECT_IDENTIFIER],
				   'messageImprint'	=>	$messageImprint,
				   'serialNumber'		=>	['type'=>ASN1::TYPE_INTEGER],
				   'genTime'			=>	['type' => ASN1::TYPE_GENERALIZED_TIME],
				   'accuracy'			=>	$accuracy,
				   
				   'ordering'			=>	[
						'type'=> ASN1::TYPE_BOOLEAN,
						'optional'=>true,
						'default'  => false
					],
					'nonce'	=> [
						'type'=>ASN1::TYPE_INTEGER,
						'optional'=>true,
					],
					
				   'tsa' =>[
					   'constant' => 0,
					   'optional' => true,
					   'implicit' => true,
					   'class'=>ASN1::CLASS_CONTEXT_SPECIFIC,
					   'cast'=>0
				   ] + Maps\GeneralNames::MAP,
				   'extensions'		=> [
					   'constant' => 1,
					   'optional' => true,
					   'implicit' => true,
				   ] + Maps\Extensions::MAP
			   ]
							   );

        // OIDs from RFC5280 and those RFCs mentioned in RFC5280#section-4.1.1.2
        $this->oids = array(
            '1.3.6.1.5.5.7' => 'id-pkix',
            '1.3.6.1.5.5.7.1' => 'id-pe',
            '1.3.6.1.5.5.7.2' => 'id-qt',
            '1.3.6.1.5.5.7.3' => 'id-kp',
            '1.3.6.1.5.5.7.48' => 'id-ad',
            '1.3.6.1.5.5.7.2.1' => 'id-qt-cps',
            '1.3.6.1.5.5.7.2.2' => 'id-qt-unotice',
            '1.3.6.1.5.5.7.48.1' =>'id-ad-ocsp',
            '1.3.6.1.5.5.7.48.2' => 'id-ad-caIssuers',
            '1.3.6.1.5.5.7.48.3' => 'id-ad-timeStamping',
            '1.3.6.1.5.5.7.48.5' => 'id-ad-caRepository',
            '2.5.4' => 'id-at',
            '2.5.4.41' => 'id-at-name',
            '2.5.4.4' => 'id-at-surname',
            '2.5.4.42' => 'id-at-givenName',
            '2.5.4.43' => 'id-at-initials',
            '2.5.4.44' => 'id-at-generationQualifier',
            '2.5.4.3' => 'id-at-commonName',
            '2.5.4.7' => 'id-at-localityName',
            '2.5.4.8' => 'id-at-stateOrProvinceName',
            '2.5.4.10' => 'id-at-organizationName',
            '2.5.4.11' => 'id-at-organizationalUnitName',
            '2.5.4.12' => 'id-at-title',
            '2.5.4.13' => 'id-at-description',
            '2.5.4.46' => 'id-at-dnQualifier',
            '2.5.4.6' => 'id-at-countryName',
            '2.5.4.5' => 'id-at-serialNumber',
            '2.5.4.65' => 'id-at-pseudonym',
            '2.5.4.17' => 'id-at-postalCode',
            '2.5.4.9' => 'id-at-streetAddress',
            '2.5.4.45' => 'id-at-uniqueIdentifier',
            '2.5.4.72' => 'id-at-role',

            '0.9.2342.19200300.100.1.25' => 'id-domainComponent',
            '1.2.840.113549.1.9' => 'pkcs-9',
            '1.2.840.113549.1.9.1' => 'pkcs-9-at-emailAddress',
            '2.5.29' => 'id-ce',
            '2.5.29.35' => 'id-ce-authorityKeyIdentifier',
            '2.5.29.14' => 'id-ce-subjectKeyIdentifier',
            '2.5.29.15' => 'id-ce-keyUsage',
            '2.5.29.16' => 'id-ce-privateKeyUsagePeriod',
            '2.5.29.32' => 'id-ce-certificatePolicies',
            '2.5.29.32.0' => 'anyPolicy',

            '2.5.29.33' => 'id-ce-policyMappings',
            '2.5.29.17' => 'id-ce-subjectAltName',
            '2.5.29.18' => 'id-ce-issuerAltName',
            '2.5.29.9' => 'id-ce-subjectDirectoryAttributes',
            '2.5.29.19' => 'id-ce-basicConstraints',
            '2.5.29.30' => 'id-ce-nameConstraints',
            '2.5.29.36' => 'id-ce-policyConstraints',
            '2.5.29.31' => 'id-ce-cRLDistributionPoints',
            '2.5.29.37' => 'id-ce-extKeyUsage',
            '2.5.29.37.0' => 'anyExtendedKeyUsage',
            '1.3.6.1.5.5.7.3.1' => 'id-kp-serverAuth',
            '1.3.6.1.5.5.7.3.2' => 'id-kp-clientAuth',
            '1.3.6.1.5.5.7.3.3' => 'id-kp-codeSigning',
            '1.3.6.1.5.5.7.3.4' => 'id-kp-emailProtection',
            '1.3.6.1.5.5.7.3.8' => 'id-kp-timeStamping',
            '1.3.6.1.5.5.7.3.9' => 'id-kp-OCSPSigning',
            '2.5.29.54' => 'id-ce-inhibitAnyPolicy',
            '2.5.29.46' => 'id-ce-freshestCRL',
            '1.3.6.1.5.5.7.1.1' => 'id-pe-authorityInfoAccess',
            '1.3.6.1.5.5.7.1.3' => 'id-pe-qcStatements',
            '1.3.6.1.5.5.7.1.11' => 'id-pe-subjectInfoAccess',
            '2.5.29.20' => 'id-ce-cRLNumber',
            '2.5.29.28' => 'id-ce-issuingDistributionPoint',
            '2.5.29.27' => 'id-ce-deltaCRLIndicator',
            '2.5.29.21' => 'id-ce-cRLReasons',
            '2.5.29.29' => 'id-ce-certificateIssuer',
            '2.5.29.23' => 'id-ce-holdInstructionCode',
            '1.2.840.10040.2' => 'holdInstruction',
            '1.2.840.10040.2.1' => 'id-holdinstruction-none',
            '1.2.840.10040.2.2' => 'id-holdinstruction-callissuer',
            '1.2.840.10040.2.3' => 'id-holdinstruction-reject',
            '2.5.29.24' => 'id-ce-invalidityDate',

            '1.2.840.113549.2.2' => 'md2',
            '1.2.840.113549.2.5' => 'md5',
            '1.3.14.3.2.26' => 'id-sha1',
            '1.2.840.10040.4.1' => 'id-dsa',
            '1.2.840.10040.4.3' => 'id-dsa-with-sha1',
            '1.2.840.113549.1.1' => 'pkcs-1',
            '1.2.840.113549.1.1.1' => 'rsaEncryption',
            '1.2.840.113549.1.1.2' => 'md2WithRSAEncryption',
            '1.2.840.113549.1.1.4' => 'md5WithRSAEncryption',
            '1.2.840.113549.1.1.5' => 'sha1WithRSAEncryption',
			
			'1.2.840.113549.1.9.16.1.0' => 'id-ct-anyContentType',
			'1.2.840.113549.1.9.16.1.1' => 'id-ct-receipt',
			'1.2.840.113549.1.9.16.1.2' => 'ct-authData',
			'1.2.840.113549.1.9.16.1.3' => 'id-ct-publishCert',
			'1.2.840.113549.1.9.16.1.4' => 'id-smime-ct-TSTInfo',
			'1.2.840.113549.1.9.16.1.5' => 'tdtInfo',
			'1.2.840.113549.1.9.16.1.6' => 'contentInfo',
			'1.2.840.113549.1.9.16.1.7' => 'id-ct-DVCSRequestData',
			'1.2.840.113549.1.9.16.1.8' => 'id-ct-DVCSResponseData',
			'1.2.840.113549.1.9.16.1.9' => 'compressedData',
			'1.2.840.113549.1.9.16.1.10' => 'certValRequest',
			'1.2.840.113549.1.9.16.1.11' => 'certValResponse',
			'1.2.840.113549.1.9.16.1.12' => 'valPolRequest',
			'1.2.840.113549.1.9.16.1.13' => 'valPolResponse',
			'1.2.840.113549.1.9.16.1.14' => 'id-ct-attrCertEncAttrs',
			'1.2.840.113549.1.9.16.1.15' => 'id-ct-TSReq',
			'1.2.840.113549.1.9.16.1.16' => 'id-ct-firmwarePackage',
			'1.2.840.113549.1.9.16.1.17' => 'id-ct-firmwareLoadReceipt',
			'1.2.840.113549.1.9.16.1.18' => 'id-ct-firmwareLoadError',
			'1.2.840.113549.1.9.16.1.19' => 'id-ct-contentCollection',
			'1.2.840.113549.1.9.16.1.20' => 'id-ct-contentWithAttrs',
			'1.2.840.113549.1.9.16.1.21' => 'id-ct-encKeyWithID',
			'1.2.840.113549.1.9.16.1.22' => 'id-ct-encPEPSI',
			'1.2.840.113549.1.9.16.1.23' => 'authEnvelopedData',
			'1.2.840.113549.1.9.16.1.24' => 'id-ct-routeOriginAuthz',
			'1.2.840.113549.1.9.16.1.25' => 'id-ct-KP-sKeyPackage',
			'1.2.840.113549.1.9.16.1.26' => 'id-ct-rpkiManifest',
			'1.2.840.113549.1.9.16.1.27' => 'asciiTextWithCRLF',
			'1.2.840.113549.1.9.16.1.28' => 'xml',
			'1.2.840.113549.1.9.16.1.29' => 'pdf',
			'1.2.840.113549.1.9.16.1.30' => 'postscript',
			'1.2.840.113549.1.9.16.1.31' => 'id-ct-timestampedData',
			'1.2.840.113549.1.9.16.1.32' => 'id-ct-ASAdjacencyAttest',
			'1.2.840.113549.1.9.16.1.33' => 'id-ct-rpkiTrustAnchor',
			'1.2.840.113549.1.9.16.1.34' => 'id-ct-trustAnchorList',
			'1.2.840.113549.1.9.16.1.35' => 'id-ct-rpkiGhostbusters',
			'1.2.840.113549.1.9.16.1.36' => 'id-ct-resourceTaggedAttest',

			
			
            '1.2.840.10046.2.1' => 'dhpublicnumber',
            '2.16.840.1.101.2.1.1.22' => 'id-keyExchangeAlgorithm',
            '1.2.840.10045' => 'ansi-X9-62',
            '1.2.840.10045.4' => 'id-ecSigType',
            '1.2.840.10045.4.1' => 'ecdsa-with-SHA1',
            '1.2.840.10045.1' => 'id-fieldType',
            '1.2.840.10045.1.1' => 'prime-field',
            '1.2.840.10045.1.2' => 'characteristic-two-field',
            '1.2.840.10045.1.2.3' => 'id-characteristic-two-basis',
            '1.2.840.10045.1.2.3.1' => 'gnBasis',
            '1.2.840.10045.1.2.3.2' => 'tpBasis',
            '1.2.840.10045.1.2.3.3' => 'ppBasis',
            '1.2.840.10045.2' => 'id-publicKeyType',
            '1.2.840.10045.2.1' => 'id-ecPublicKey',
            '1.2.840.10045.3' => 'ellipticCurve',
            '1.2.840.10045.3.0' => 'c-TwoCurve',
            '1.2.840.10045.3.0.1' => 'c2pnb163v1',
            '1.2.840.10045.3.0.2' => 'c2pnb163v2',
            '1.2.840.10045.3.0.3' => 'c2pnb163v3',
            '1.2.840.10045.3.0.4' => 'c2pnb176w1',
            '1.2.840.10045.3.0.5' => 'c2pnb191v1',
            '1.2.840.10045.3.0.6' => 'c2pnb191v2',
            '1.2.840.10045.3.0.7' => 'c2pnb191v3',
            '1.2.840.10045.3.0.8' => 'c2pnb191v4',
            '1.2.840.10045.3.0.9' => 'c2pnb191v5',
            '1.2.840.10045.3.0.10' => 'c2pnb208w1',
            '1.2.840.10045.3.0.11' => 'c2pnb239v1',
            '1.2.840.10045.3.0.12' => 'c2pnb239v2',
            '1.2.840.10045.3.0.13' => 'c2pnb239v3',
            '1.2.840.10045.3.0.14' => 'c2pnb239v4',
            '1.2.840.10045.3.0.15' => 'c2pnb239v5',
            '1.2.840.10045.3.0.16' => 'c2pnb272w1',
            '1.2.840.10045.3.0.17' => 'c2pnb304w1',
            '1.2.840.10045.3.0.18' => 'c2pnb359v1',
            '1.2.840.10045.3.0.19' => 'c2pnb368w1',
            '1.2.840.10045.3.0.20' => 'c2pnb431r1',
            '1.2.840.10045.3.1' => 'primeCurve',
            '1.2.840.10045.3.1.1' => 'prime192v1',
            '1.2.840.10045.3.1.2' => 'prime192v2',
            '1.2.840.10045.3.1.3' => 'prime192v3',
            '1.2.840.10045.3.1.4' => 'prime239v1',
            '1.2.840.10045.3.1.5' => 'prime239v2',
            '1.2.840.10045.3.1.6' => 'prime239v3',
            '1.2.840.10045.3.1.7' => 'prime256v1',
            '1.2.840.113549.1.1.7' => 'id-RSAES-OAEP',
            '1.2.840.113549.1.1.9' => 'id-pSpecified',
            '1.2.840.113549.1.1.10' => 'id-RSASSA-PSS',
            '1.2.840.113549.1.1.8' => 'id-mgf1',
            '1.2.840.113549.1.1.14' => 'sha224WithRSAEncryption',
            '1.2.840.113549.1.1.11' => 'sha256WithRSAEncryption',
            '1.2.840.113549.1.1.12' => 'sha384WithRSAEncryption',
            '1.2.840.113549.1.1.13' => 'sha512WithRSAEncryption',
            '2.16.840.1.101.3.4.2.1' => 'id-sha256',
            '2.16.840.1.101.3.4.2.2' => 'id-sha384',
            '2.16.840.1.101.3.4.2.3' => 'id-sha512',
            '2.16.840.1.101.3.4.2.4' => 'id-sha224',
			
			'2.16.840.1.101.3.4.2.5' => 'id-sha512-224',
			'2.16.840.1.101.3.4.2.6' => 'id-sha512-256',
			'2.16.840.1.101.3.4.2.7' => 'id-sha3-224',
			'2.16.840.1.101.3.4.2.8' => 'id-sha3-256',
			'2.16.840.1.101.3.4.2.9' => 'id-sha3-384',
			'2.16.840.1.101.3.4.2.10' => 'id-sha3-512',
			'2.16.840.1.101.3.4.2.11' => 'id-shake128',
			'2.16.840.1.101.3.4.2.12' => 'id-shake256',

			
            '1.2.643.2.2.4' => 'id-GostR3411-94-with-GostR3410-94',
            '1.2.643.2.2.3' => 'id-GostR3411-94-with-GostR3410-2001',
            '1.2.643.2.2.20' => 'id-GostR3410-2001',
            '1.2.643.2.2.19' => 'id-GostR3410-94',
            // Netscape Object Identifiers from "Netscape Certificate Extensions"
            '2.16.840.1.113730' => 'netscape',
            '2.16.840.1.113730.1' => 'netscape-cert-extension',
            '2.16.840.1.113730.1.1' => 'netscape-cert-type',
            '2.16.840.1.113730.1.13' => 'netscape-comment',
            '2.16.840.1.113730.1.8' => 'netscape-ca-policy-url',
            // the following are X.509 extensions not supported by phpseclib
            '1.3.6.1.5.5.7.1.12' => 'id-pe-logotype',
            '1.2.840.113533.7.65.0' => 'entrustVersInfo',
            '2.16.840.1.113733.1.6.9' => 'verisignPrivate',
            // for Certificate Signing Requests
            // see http://tools.ietf.org/html/rfc2985
            '1.2.840.113549.1.9.2' => 'pkcs-9-at-unstructuredName', // PKCS #9 unstructured name
            '1.2.840.113549.1.9.7' => 'pkcs-9-at-challengePassword', // Challenge password for certificate revocations
            '1.2.840.113549.1.9.14' => 'pkcs-9-at-extensionRequest', // Certificate extension request

            // from http://www.etsi.org/deliver/etsi_ts/101800_101899/101862/01.03.01_60/ts_101862v010301p.pdf
            '0.4.0.1862.1' => 'id-etsi-qcs',
            '0.4.0.1862.1.1' => 'id-etsi-qcs-QcCompliance',
            '0.4.0.1862.1.2' => 'id-etsi-qcs-QcLimitValue',
            '0.4.0.1862.1.3' => 'id-etsi-qcs-QcRetentionPeriod',
            '0.4.0.1862.1.4' => 'id-etsi-qcs-QcSSCD',

            // from RFC3039
            '1.3.6.1.5.5.7.9.1' => 'id-pda-dateOfBirth',
            '1.3.6.1.5.5.7.9.2' => 'id-pda-placeOfBirth',
            '1.3.6.1.5.5.7.9.3' => 'id-pda-gender',
            '1.3.6.1.5.5.7.9.4' => 'id-pda-countyOfCitizenship',
            '1.3.6.1.5.5.7.9.5' => 'id-pda-countyOfResidence',
            '1.3.6.1.5.5.7.9.6' => 'id-pda-dateOfBirth',
        );
		}
		

        $ContentType = array('type' => ASN1::TYPE_OBJECT_IDENTIFIER);

        $this->ContentInfo = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'contentType' => $ContentType,
                'content' => array(
                    'type' => ASN1::TYPE_ANY,
                    'constant' => 0,
                    'optional' => true,
                    'explicit' => true
                )
            )
        );

        $CMSVersion = array(
            'type'    => ASN1::TYPE_INTEGER,
            'mapping' => array('v0', 'v1', 'v2', 'v4', 'v5')
        );

        $AlgorithmIdentifier = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'algorithm'  => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
                'parameters' => array(
                                    'type'     => ASN1::TYPE_ANY,
                                    'optional' => true
                                )
            )
        );


        $DigestAlgorithmIdentifier = $AlgorithmIdentifier;

        $DigestAlgorithmIdentifiers = array(
            'type' => ASN1::TYPE_SET,
            'min' => 1,
            'max' => -1,
            'children' => $DigestAlgorithmIdentifier
        );

        $EncapsulatedContentInfo = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'eContentType' => $ContentType,
                'eContent' => array(
                                  'type' => ASN1::TYPE_OCTET_STRING,
                                  'constant' => 0,
                                  'optional' => true,
                                  'explicit' => true
                              )
            )
        );
		
		
		

        $CertificateSerialNumber = array('type' => ASN1::TYPE_INTEGER);

        $AttCertValidityPeriod = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'notBeforeTime' => array('type' => ASN1::TYPE_GENERALIZED_TIME),
                'notAfterTime' => array('type' => ASN1::TYPE_GENERALIZED_TIME)
            )
        );

        $UniqueIdentifier = array('type' => ASN1::TYPE_BIT_STRING);

        $AttributeType = array('type' => ASN1::TYPE_OBJECT_IDENTIFIER);

        $Attribute = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'type' => $AttributeType,
                'value'=> array(
                              'type'     => ASN1::TYPE_SET,
                              'min'      => 1,
                              'max'      => -1,
                              'children' => $this->AttributeValue
                          )
            )
        );

        $Attributes = array(
            'type'     => ASN1::TYPE_SET,
            'min'      => 1,
            'max'      => -1,
            'children' => $Attribute
        );

        $AnotherName = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                 'type-id' => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
                 'value'   => array(
                                  'type' => ASN1::TYPE_ANY,
                                  'constant' => 0,
                                  'optional' => true,
                                  'explicit' => true
                              )
            )
        );

        $ExtensionAttribute = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                 'extension-attribute-type'  => array(
                                                    'type' => ASN1::TYPE_PRINTABLE_STRING,
                                                    'constant' => 0,
                                                    'optional' => true,
                                                    'implicit' => true
                                                ),
                 'extension-attribute-value' => array(
                                                    'type' => ASN1::TYPE_ANY,
                                                    'constant' => 1,
                                                    'optional' => true,
                                                    'explicit' => true
                                                )
            )
        );

        $ExtensionAttributes = array(
            'type'     => ASN1::TYPE_SET,
            'min'      => 1,
            'max'      => 256, // ub-extension-attributes
            'children' => $ExtensionAttribute
        );

        $BuiltInDomainDefinedAttribute = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                 'type'  => array('type' => ASN1::TYPE_PRINTABLE_STRING),
                 'value' => array('type' => ASN1::TYPE_PRINTABLE_STRING)
            )
        );

        $BuiltInDomainDefinedAttributes = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => 4, // ub-domain-defined-attributes
            'children' => $BuiltInDomainDefinedAttribute
        );

        $OrganizationalUnitNames = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => 4, // ub-organizational-units
            'children' => array('type' => ASN1::TYPE_PRINTABLE_STRING)
        );

        $PersonalName = array(
            'type'     => ASN1::TYPE_SET,
            'children' => array(
                'surname'              => array(
                                           'type' => ASN1::TYPE_PRINTABLE_STRING,
                                           'constant' => 0,
                                           'optional' => true,
                                           'implicit' => true
                                         ),
                'given-name'           => array(
                                           'type' => ASN1::TYPE_PRINTABLE_STRING,
                                           'constant' => 1,
                                           'optional' => true,
                                           'implicit' => true
                                         ),
                'initials'             => array(
                                           'type' => ASN1::TYPE_PRINTABLE_STRING,
                                           'constant' => 2,
                                           'optional' => true,
                                           'implicit' => true
                                         ),
                'generation-qualifier' => array(
                                           'type' => ASN1::TYPE_PRINTABLE_STRING,
                                           'constant' => 3,
                                           'optional' => true,
                                           'implicit' => true
                                         )
            )
        );

        $NumericUserIdentifier = array('type' => ASN1::TYPE_NUMERIC_STRING);

        $OrganizationName = array('type' => ASN1::TYPE_PRINTABLE_STRING);

        $PrivateDomainName = array(
            'type'     => ASN1::TYPE_CHOICE,
            'children' => array(
                'numeric'   => array('type' => ASN1::TYPE_NUMERIC_STRING),
                'printable' => array('type' => ASN1::TYPE_PRINTABLE_STRING)
            )
        );

        $TerminalIdentifier = array('type' => ASN1::TYPE_PRINTABLE_STRING);

        $NetworkAddress = array('type' => ASN1::TYPE_NUMERIC_STRING);

        $AdministrationDomainName = array(
            'type'     => ASN1::TYPE_CHOICE,
            // if class isn't present it's assumed to be ASN1::CLASS_UNIVERSAL or
            // (if constant is present) ASN1::CLASS_CONTEXT_SPECIFIC
            'class'    => ASN1::CLASS_APPLICATION,
            'cast'     => 2,
            'children' => array(
                'numeric'   => array('type' => ASN1::TYPE_NUMERIC_STRING),
                'printable' => array('type' => ASN1::TYPE_PRINTABLE_STRING)
            )
        );

        $CountryName = array(
            'type'     => ASN1::TYPE_CHOICE,
            // if class isn't present it's assumed to be ASN1::CLASS_UNIVERSAL or
            // (if constant is present) ASN1::CLASS_CONTEXT_SPECIFIC
            'class'    => ASN1::CLASS_APPLICATION,
            'cast'     => 1,
            'children' => array(
                'x121-dcc-code'        => array('type' => ASN1::TYPE_NUMERIC_STRING),
                'iso-3166-alpha2-code' => array('type' => ASN1::TYPE_PRINTABLE_STRING)
            )
        );

        $BuiltInStandardAttributes =  array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'country-name'               => array('optional' => true) + $CountryName,
                'administration-domain-name' => array('optional' => true) + $AdministrationDomainName,
                'network-address'            => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $NetworkAddress,
                'terminal-identifier'        => array(
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $TerminalIdentifier,
                'private-domain-name'        => array(
                                                 'constant' => 2,
                                                 'optional' => true,
                                                 'explicit' => true
                                               ) + $PrivateDomainName,
                'organization-name'          => array(
                                                 'constant' => 3,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $OrganizationName,
                'numeric-user-identifier'    => array(
                                                 'constant' => 4,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $NumericUserIdentifier,
                'personal-name'              => array(
                                                 'constant' => 5,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $PersonalName,
                'organizational-unit-names'  => array(
                                                 'constant' => 6,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $OrganizationalUnitNames
            )
        );

        $ORAddress = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                 'built-in-standard-attributes'       => $BuiltInStandardAttributes,
                 'built-in-domain-defined-attributes' => array('optional' => true) + $BuiltInDomainDefinedAttributes,
                 'extension-attributes'               => array('optional' => true) + $ExtensionAttributes
            )
        );

        $EDIPartyName = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                 'nameAssigner' => array(
                                    'constant' => 0,
                                    'optional' => true,
                                    'implicit' => true
                                ) + $this->DirectoryString,
                 // partyName is technically required but File_ASN1 doesn't currently support non-optional constants and
                 // setting it to optional gets the job done in any event.
                 'partyName'    => array(
                                    'constant' => 1,
                                    'optional' => true,
                                    'implicit' => true
                                ) + $this->DirectoryString
            )
        );

        $GeneralName = array(
            'type'     => ASN1::TYPE_CHOICE,
            'children' => array(
                'otherName'                 => array(
                                                 'constant' => 0,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $AnotherName,
                'rfc822Name'                => array(
                                                 'type' => ASN1::TYPE_IA5_STRING,
                                                 'constant' => 1,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'dNSName'                   => array(
                                                 'type' => ASN1::TYPE_IA5_STRING,
                                                 'constant' => 2,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'x400Address'               => array(
                                                 'constant' => 3,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $ORAddress,
                'directoryName'             => array(
                                                 'constant' => 4,
                                                 'optional' => true,
                                                 'explicit' => true
                                               ) + $this->Name,
                'ediPartyName'              => array(
                                                 'constant' => 5,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ) + $EDIPartyName,
                'uniformResourceIdentifier' => array(
                                                 'type' => ASN1::TYPE_IA5_STRING,
                                                 'constant' => 6,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'iPAddress'                 => array(
                                                 'type' => ASN1::TYPE_OCTET_STRING,
                                                 'constant' => 7,
                                                 'optional' => true,
                                                 'implicit' => true
                                               ),
                'registeredID'              => array(
                                                 'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                                                 'constant' => 8,
                                                 'optional' => true,
                                                 'implicit' => true
                                               )
            )
        );

        $GeneralNames = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'min'      => 1,
            'max'      => -1,
            'children' => $GeneralName
        );

        $IssuerSerial = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'issuer' => $GeneralNames,
                'serialNumber' => $CertificateSerialNumber
            )
        );

        $ExtendedCertificateInfo = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'version' => array('type' => ASN1::TYPE_INTEGER),
                'certificate' => $this->Certificate,
                'attributes' => $Attributes
            )
        );

        // from ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-6.asc
        $ExtendedCertificate = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'extendedCertificateInfo' => $ExtendedCertificateInfo,
                'signatureAlgorithm' => $AlgorithmIdentifier,
                'signature' => array('type' => ASN1::TYPE_BIT_STRING)
            )
        );

        $AttCertVersion = array(
            'type'    => ASN1::TYPE_INTEGER,
            'mapping' => array('v2')
        );

        $ObjectDigestInfo = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'digestedObjectType' => array(
                                            'type' => ASN1::TYPE_ENUMERATED,
                                            'children' => array(
                                                              'publicKey',
                                                              'publicKeyCert',
                                                              'otherObjectTypes'
                                                          )
                                            ),
                'otherObjectTypeID' => array(
                                           'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
                                           'optional' => true
                                       ),
                'digestAlgorithm' => $AlgorithmIdentifier,
                'objectDigest' => array('type' => ASN1::TYPE_BIT_STRING)
            )
        );

        $Holder = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'baseCertificateID' => array(
                                           'constant' => 0,
                                           'optional' => true
                                       ) + $IssuerSerial,
                'entityName' => array(
                                    'constant' => 1,
                                    'optional' => true
                                ) + $GeneralNames,
                'objectDigestInfo' => array(
                                          'constant' => 2,
                                          'optional' => true
                                      ) + $ObjectDigestInfo
            )
        );

        $V2Form = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                              'issuerName' => array('optional' => true) + $GeneralNames,
                              'baseCertificateID' => array(
                                                         'constant' => 0,
                                                         'optional' => true
                                                     ) + $IssuerSerial,
                              'objectDigestInfo' => array(
                                                        'constant' => 1,
                                                        'optional' => true
                                                    ) + $ObjectDigestInfo
                          )
        );

        $AttCertIssuer = array(
            'type' => ASN1::TYPE_CHOICE,
            'children' => array(
                              'v1Form' => $GeneralNames,
                              'v2Form' => array(
                                              'constant' => 0,
                                              'optional' => true,
                                          ) + $V2Form
                          )
        );


        $AttributeCertificateInfo = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'version' => array(
                                 'optional' => true,
                                 'default' => 'v2'
                             ) + $AttCertVersion,
                'holder' => $Holder,
                'issuer' => $AttCertIssuer,
                'signature' => $AlgorithmIdentifier,
                'serialNumber' => $CertificateSerialNumber,
                'attrCertValidityPeriod' => $AttCertValidityPeriod,
                'attributes' => array(
                                    'type'     => ASN1::TYPE_SEQUENCE,
                                    'min'      => 0,
                                    'max'      => -1,
                                    'children' => $Attribute
                                ),
                'issuerUniqueID' => array('optional' => true) + $UniqueIdentifier,
                'extensions' => array('optional' => true) + $this->Extensions
            )
        );

        // from https://tools.ietf.org/html/rfc3281
        $AttributeCertificateV2 = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'acinfo' => $AttributeCertificateInfo,
                'signatureAlgorithm' => $AlgorithmIdentifier,
                'signature' => array('type' => ASN1::TYPE_BIT_STRING)
            )
        );

        $AttCertVersionV1 = array(
            'type'    => ASN1::TYPE_INTEGER,
            'mapping' => array('v1')
        );

        $AttributeCertificateInfoV1 = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'version' => array(
                                 'optional' => true,
                                 'default' => 'v1'
                             ) + $AttCertVersionV1,
                'subject' => array(
                                 'type' => ASN1::TYPE_CHOICE,
                                 'children' => array(
                                                   'baseCertificateID' => array(
                                                       'constant' => 0,
                                                       'optional' => true
                                                   ) + $IssuerSerial,
                                                   'subjectName' => array(
                                                       'constant' => 1,
                                                       'optional' => true
                                                   ) + $GeneralNames
                                               )
                                 ),
                'issuer' => $GeneralNames,
                'signature' => $AlgorithmIdentifier,
                'serialNumber' => $CertificateSerialNumber,
                'attCertValidityPeriod' => $AttCertValidityPeriod,
                'attributes' => array(
                                    'type'     => ASN1::TYPE_SEQUENCE,
                                    'min'      => 0,
                                    'max'      => -1,
                                    'children' => $Attribute
                                ),
                'issuerUniqueID' => array('optional' => true) + $UniqueIdentifier,
                'extensions' => array('optional' => true) + $this->Extensions
            )
        );

        $AttributeCertificateV1 = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'acInfo' => $AttributeCertificateInfoV1,
                'signatureAlgorithm' => $AlgorithmIdentifier,
                'signature' => array('type' => ASN1::TYPE_BIT_STRING)
            )
        );

        $OtherCertificateFormat = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'otherCertFormat' => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
                'otherCert' => array('type' => ASN1::TYPE_ANY)
            )
        );

        $CertificateChoices = array(
            'type' => ASN1::TYPE_CHOICE,
            'children' => array(
                'certificate' => $this->Certificate,
                'extendedCertificate' => array(
                                             //'type' => ASN1::TYPE_ANY,
                                             'constant' => 0,
                                             'optional' => true,
                                             'implicit' => true
                                         ) + $ExtendedCertificate,
                'v1AttrCert' => array(
                                    'type' => ASN1::TYPE_ANY,
                                    'constant' => 1,
                                    'optional' => true,
                                    'implicit' => true
                                ) ,//+ $AttributeCertificateV1,
                'v2AttrCert' => array(
                                    //'type' => ASN1::TYPE_ANY,
                                    'constant' => 2,
                                    'optional' => true,
                                    'implicit' => true
                                ) + $AttributeCertificateV2,
                'other' => array(
                               //'type' => ASN1::TYPE_ANY,
                               'constant' => 3,
                               'optional' => true,
                               'implicit' => true
                           ) +  $OtherCertificateFormat
            )
        );

        $CertificateSet = array(
            'type' => ASN1::TYPE_SET,
            'min' => 1,
            'max' => -1,
            'children' => $CertificateChoices
        );

        $OtherRevocationInfoFormat = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'otherRevInfoFormat' => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
                'otherRevInfo' => array('type' => ASN1::TYPE_ANY)
            )
        );

        $RevocationInfoChoice = array(
            'type' => ASN1::TYPE_CHOICE,
            'children' => array(
                'crl' => $this->CertificateList,
                'other' => array(
                               'constant' => 1,
                               'optional' => true,
                               'implicit' => true
                           ) + $OtherRevocationInfoFormat
            )
        );

        $RevocationInfoChoices = array(
            'type' => ASN1::TYPE_SET,
            'min' => 1,
            'max' => -1,
            'children' => $RevocationInfoChoice
        );

        $IssuerAndSerialNumber = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'issuer' => $this->Name,
                'serialNumber' => $CertificateSerialNumber
            )
        );

        $SubjectKeyIdentifier = array('type' => ASN1::TYPE_OCTET_STRING);

        $SignerIdentifier = array(
            'type' => ASN1::TYPE_CHOICE,
            'children' => array(
                'issuerAndSerialNumber' => $IssuerAndSerialNumber,
                'subjectKeyIdentifier' => array(
                                              'constant' => 0,
                                              'optional' => true
                                          ) + $SubjectKeyIdentifier
            )
        );

        $SignedAttributes = array(
            'type'     => ASN1::TYPE_SET,
            'min'      => 1,
            'max'      => -1,
            'children' => $Attribute
        );

        $UnsignedAttributes = array(
            'type'     => ASN1::TYPE_SET,
            'min'      => 1,
            'max'      => -1,
            'children' => $Attribute
        );

        $SignatureAlgorithmIdentifier = $AlgorithmIdentifier;

        $SignatureValue = array('type' => ASN1::TYPE_OCTET_STRING);

        $this->SignerInfo = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'version' => $CMSVersion,
                'sid' => $SignerIdentifier,
                'digestAlgorithm' => $DigestAlgorithmIdentifier,
                'signedAttrs' => array(
                                     'constant' => 0,
                                     'optional' => true,
                                     'implicit' => true
                                 ) + $SignedAttributes,
                'signatureAlgorithm' => $SignatureAlgorithmIdentifier,
                'signature' => $SignatureValue,
                'unsignedAttrs' => array(
                                       'constant' => 1,
                                       'optional' => true,
                                       'implicit' => true
                                   ) + $UnsignedAttributes
            )
        );

        $SignerInfos = array(
            'type' => ASN1::TYPE_SET,
            'min' => 1,
            'max' => -1,
            'children' => $this->SignerInfo
        );

        $this->SignedData = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'version' => $CMSVersion,
                'digestAlgorithms' => $DigestAlgorithmIdentifiers,
                'encapContentInfo' => $EncapsulatedContentInfo,
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

		include_once("AuthentiCodePKCS.php");

        $CompressionAlgorithmIdentifier = $AlgorithmIdentifier;

        $this->CompressedData = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'version' => $CMSVersion,
                'compressionAlgorithm' => $CompressionAlgorithmIdentifier,
                'encapContentInfo' => $EncapsulatedContentInfo
            )
        );

        $Hash = array('type' => ASN1::TYPE_OCTET_STRING);

        $ESSCertID = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'certHash' => $Hash, // sha1 hash of entire cert
                'issuerSerial' => array('optional' => true) + $IssuerSerial
            )
        );

        $PolicyQualifierId = array('type' => ASN1::TYPE_OBJECT_IDENTIFIER);

        $PolicyQualifierInfo = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'policyQualifierId' => $PolicyQualifierId,
                'qualifier'         => array('type' => ASN1::TYPE_ANY)
            )
        );

        $CertPolicyId = array('type' => ASN1::TYPE_OBJECT_IDENTIFIER);

        $PolicyInformation = array(
            'type'     => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'policyIdentifier' => $CertPolicyId,
                'policyQualifiers' => array(
                                          'type'     => ASN1::TYPE_SEQUENCE,
                                          'min'      => 0,
                                          'max'      => -1,
                                          'optional' => true,
                                          'children' => $PolicyQualifierInfo
                                      )
            )
        );

        $this->SigningCertificate = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'certs' => array(
                               'type'     => ASN1::TYPE_SEQUENCE,
                               'min'      => 1,
                               'max'      => -1,
                               'children' => $ESSCertID
                           ),
                'policies' => array(
                                  'type'     => ASN1::TYPE_SEQUENCE,
                                  'min'      => 1,
                                  'max'      => -1,
                                  'optional' => true,
                                  'children' => $PolicyInformation
                              )
            )
        );

        $ESSCertIDv2 = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'hashAlgorithm' => array(
                                       'optional' => true,
                                       'default' => array('algorithm' => 'id-sha256', 'parameters' => array('null' => '')),
                                   ) + $AlgorithmIdentifier,
                'certHash' => $Hash,
                'issuerSerial' => array('optional' => true) + $IssuerSerial
            )
        );

        $this->SigningCertificateV2 = array(
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => array(
                'certs' => array(
                               'type'     => ASN1::TYPE_SEQUENCE,
                               'min'      => 1,
                               'max'      => -1,
                               'children' => $ESSCertIDv2
                           ),
                'policies' => array(
                                  'type'     => ASN1::TYPE_SEQUENCE,
                                  'min'      => 1,
                                  'max'      => -1,
                                  'optional' => true,
                                  'children' => $PolicyInformation
                              )
            )
        );

        $this->oids = array(
            '1.2.840.113549.1.7.1' => 'id-data', // https://tools.ietf.org/html/rfc5652#section-4
            '1.2.840.113549.1.7.2' => 'id-signedData', // https://tools.ietf.org/html/rfc5652#section-5
            '1.2.840.113549.1.9.16.1.9' => 'id-ct-compressedData', // // https://tools.ietf.org/html/rfc3274#section-1.1
            // the rest are currently unsupported
            '1.2.840.113549.1.7.3' => 'id-envelopedData', // https://tools.ietf.org/html/rfc5652#section-6
            '1.2.840.113549.1.7.5' => 'id-digestedData', // https://tools.ietf.org/html/rfc5652#section-7
            '1.2.840.113549.1.7.6' => 'id-encryptedData', // https://tools.ietf.org/html/rfc5652#section-8
            '1.2.840.113549.1.9.16.1.2' => 'id-ct-authData', // https://tools.ietf.org/html/rfc5652#section-9

            '1.2.840.113549.1.9.3' => 'id-contentType', // https://tools.ietf.org/html/rfc5652#section-11.1
            '1.2.840.113549.1.9.4' => 'id-messageDigest', // https://tools.ietf.org/html/rfc5652#section-11.2
            '1.2.840.113549.1.9.5' => 'id-signingTime', // https://tools.ietf.org/html/rfc5652#section-11.3
            '1.2.840.113549.1.9.6' => 'id-countersignature', // https://tools.ietf.org/html/rfc5652#section-11.4

            '1.2.840.113549.1.9.15' => 'pkcs-9-at-smimeCapabilities', // https://tools.ietf.org/html/rfc2985

            '1.2.840.113549.1.9.16.2.12' => 'id-aa-signingCertificate', // https://tools.ietf.org/html/rfc2634#section-5.4
            '1.2.840.113549.1.9.16.2.47' => 'id-aa-signingCertificateV2', // https://tools.ietf.org/html/rfc5035#section-3

            '1.2.840.113549.1.9.16.2.7' => 'id-aa-contentIdentifier',

            // from RFC5754
            '2.16.840.1.101.3.4.2.4' => 'id-sha224',
            '2.16.840.1.101.3.4.2.1' => 'id-sha256',
            '2.16.840.1.101.3.4.2.2' => 'id-sha384',
            '2.16.840.1.101.3.4.2.3' => 'id-sha512',

            // from RFC3274
            '1.2.840.113549.1.9.16.3.8' => 'id-alg-zlibCompress',
			
			// Microsoft AuthentiCode specific
			'1.3.6.1.4.1.311.2.1.4'=>'id-SPC_INDIRECT_DATA_OBJID',
			'1.3.6.1.4.1.311.2.1.11'=>'id-SPC_STATEMENT_TYPE_OBJID',
			'1.3.6.1.4.1.311.2.1.12'=>'id-SPC_SP_OPUS_INFO_OBJID',
			'1.3.6.1.4.1.311.2.1.15'=>'id-SPC_PE_IMAGE_DATA_OBJID',
			'1.3.6.1.4.1.311.2.1.10'=>'id-SPC_SP_AGENCY_INFO_OBJID',
			'1.3.6.1.4.1.311.2.1.26'=>'id-SPC_MINIMAL_CRITERIA_OBJID',
			'1.3.6.1.4.1.311.2.1.27'=>'id-SPC_FINANCIAL_CRITERIA_OBJID',
			'1.3.6.1.4.1.311.2.1.28'=>'id-SPC_LINK_OBJID',
			'1.3.6.1.4.1.311.2.1.29'=>'id-SPC_HASH_INFO_OBJID',
			'1.3.6.1.4.1.311.2.1.30'=>'id-SPC_SIPINFO_OBJID',
			'1.3.6.1.4.1.311.2.1.14'=>'id-SPC_CERT_EXTENSIONS_OBJID',
			'1.3.6.1.4.1.311.2.1.18'=>'id-SPC_RAW_FILE_DATA_OBJID',
			'1.3.6.1.4.1.311.2.1.19'=>'id-SPC_STRUCTURED_STORAGE_DATA_OBJID',
			'1.3.6.1.4.1.311.2.1.20'=>'id-SPC_JAVA_CLASS_DATA_OBJID',
			'1.3.6.1.4.1.311.2.1.21'=>'id-SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID',
			'1.3.6.1.4.1.311.2.1.22'=>'id-SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID',
			'1.3.6.1.4.1.311.2.1.25'=>'id-SPC_CAB_DATA_OBJID',
			'1.3.6.1.4.1.311.2.1.25'=>'id-SPC_GLUE_RDN_OBJID',
			'1.3.6.1.4.1.311.2.2.1'=>'id-szOID_TRUSTED_CODESIGNING_CA_LIST',
			'1.3.6.1.4.1.311.2.2.2'=>'id-szOID_TRUSTED_CLIENT_AUTH_CA_LIST',
			'1.3.6.1.4.1.311.2.2.3'=>'id-szOID_TRUSTED_SERVER_AUTH_CA_LIST',
			'1.3.6.1.4.1.311.3.3.1'=>'id-szOID_RFC3161_counterSign',
			'1.3.6.1.4.1.311.2.4.1'=>'szOID_NESTED_SIGNATURE',
			
			'1.3.6.1.4.1.311.21.1'=>'szOID_CERTSRV_CA_VERSION',
			'1.3.6.1.4.1.311.21.2'=>'szOID_CERTSRV_PREVIOUS_CERT_HASH',
			'1.3.6.1.4.1.311.20.2'=>'szOID_ENROLL_CERTTYPE_EXTENSION',
			
//			'1.3.6.1.4.1.311.61.6.1' => 'szOID_KP_KERNEL_MODE_CODE_SIGNING',
			'1.3.6.1.4.1.311.10.3.21' => 'szOID_WINDOWS_RT_SIGNER',
			
			'1.3.6.1.4.1.4146.2.1' => 'cds-timestamping-tst-policy',
			'1.3.6.1.4.1.4146.2.2' => 'rfc3161-tst-policy-sha1',
			'1.3.6.1.4.1.4146.2.3' => 'rfc3161-tst-policy-sha2',

        ) + $this->oids;

        $this->baseSignedData = array(
            'contentType' => 'id-signedData',
            'content' => array(
                'version' => 'v1',
                'digestAlgorithms' => array(),
                'encapContentInfo' => array(
                    'eContentType' => 'id-data',
                    'eContent' => ''
                ),
                'certificates' => array(),
                //'crls' => array(),
                'signerInfos' => array()
            )
        );
        $this->baseSignerInfo = array(
            'version' => 'v1',
            'sid' => array(
                'issuerAndSerialNumber' => array(
                    'issuer' => array(),
                    'serialNumber' => new BigInteger()
                )
            ),
            'digestAlgorithm' => array(
                'algorithm' => array()
            ),
            'signedAttrs' => array(),
            'signatureAlgorithm' => array(
                'algorithm' => 'rsaEncryption',
                'parameters' => array('null' => '')
            ),
            'signature' => ''
        );
//        $this->currentCMS[] = $this->baseSignedData;
        $this->keys = array();
    }

    function load($src)
    {
//        $this->signatureSubjects = $this->certs = array();

        $asn1 = new ASN1();
        $src = ASN1::extractBER($src);

        if ($src === false) {
            $this->currentCMS = false;
            return false;
        }

        $asn1->loadOIDs($this->oids);
        $decoded = $asn1->decodeBER($src);

        if (!empty($decoded)) {
            $cms = $asn1->asn1map($decoded[0], $this->ContentInfo);
		}
//		var_dump($cms);
        if (!isset($cms) || $cms == false || $cms === NULL) {
            $this->currentCMS = false;
            return false;
        }

        switch ($cms['contentType']) {
            case 'id-ct-compressedData':
                $compressedData = $cms['content']->element;
                $decoded = $asn1->decodeBER($cms['content']->element);
                $cms['content'] = $asn1->asn1map($decoded[0], $this->CompressedData);

                return $cms;
            case 'id-signedData':
                $signatureContainer = $cms['content']->element;
				
                $decoded = $asn1->decodeBER($cms['content']->element);

				$cms['content'] = $this->parseSignedData($signatureContainer);
				$this->validateSignedData($cms['content']);

				$content = $cms['content']['contentInfo']['content']->element;
				$contentHeaderLen = $cms['content']['contentInfo']['content']->headerLength;
				$contentBody = substr($content,$contentHeaderLen);
				$SpcIndirectDataContentDecoded = ASN1::decodeBER($content);

				$cms['content']['contentInfo']['SpcIndirectDataContent'] = $asn1->asn1map($SpcIndirectDataContentDecoded[0], $this->SpcIndirectDataContent);
				
				foreach ($cms['content']['signerInfos'] as $i => &$signerInfo) {
					if(isset($signerInfo['unsignedAttrs']))
						foreach ($signerInfo['unsignedAttrs'] as $j => &$unsignedAttr) {
							//var_dump($unsignedAttr['type']);
							switch($unsignedAttr['type']) {
								case "id-szOID_RFC3161_counterSign":
									$RFC3161CounterSignDecoded = ASN1::decodeBER($unsignedAttr['value'][0]->element);
									$certificateSet = ($asn1->asn1map($RFC3161CounterSignDecoded[0],$this->ContentInfo));
									$certificateSetRaw = $certificateSet['content']->element;
									$certificateSetDecoded = (ASN1::decodeBER($certificateSetRaw));
									
									$certificateSet['content'] = $this->parseSignedData($certificateSetRaw,false);
									//var_dump($certificateSet['content']);
									$this->validateSignedData($certificateSet['content']);

									if($certificateSet['content']['encapContentInfo']['eContentType']=='id-smime-ct-TSTInfo')
									{
										$TSTInfoRaw = $certificateSet['content']['encapContentInfo']['eContent'];
//										file_put_contents("TST.asn1",$TSTInfoRaw);

										$TSTInfoDecoded = ASN1::decodeBER($TSTInfoRaw);

										$TSTInfo = ASN1::asn1map($TSTInfoDecoded[0],$this->TSTInfo);
										
										$TSTHashAlgo = preg_replace('#^id-#', '', $TSTInfo['messageImprint']['hashAlgorithm']['algorithm']);
										$TSTHashDigest = bin2hex($TSTInfo['messageImprint']['hashedMessage']);
										$calculatedDigest = hash($TSTHashAlgo,$signerInfo['signature']);
	//									var_dump($TSTHashAlgo,$TSTHashDigest,$calculatedDigest);
										$TSTInfo['validation']['valid'] = ($TSTHashDigest==$calculatedDigest);
										$TSTInfo['validation']['digestAlgorithm'] = $TSTHashAlgo;
										$TSTInfo['validation']['storedDigest'] = $TSTHashDigest;
										$TSTInfo['validation']['calculatedDigest'] = $calculatedDigest;
										
										$certificateSet['content']['encapContentInfo']['TSTInfo'] = $TSTInfo;									
									}
									$unsignedAttr['value'] = $certificateSet;
								break;
								
								case "id-countersignature":
									$countersignRaw = $unsignedAttr['value'][0]->element;
									$countersignDecoded = ASN1::decodeBER($countersignRaw);
									$counterSignerinfo = ($asn1->asn1map($countersignDecoded[0],$this->SignerInfo));
//									var_dump($counterSignerinfo);
									if (isset($counterSignerinfo['signedAttrs']) && count($counterSignerinfo['signedAttrs'])) {
										//var_dump($countersignDecoded);
										
										$asn1desc = $countersignDecoded[0]['content'][3];
										$temp = substr($countersignRaw, $asn1desc['start'], $asn1desc['length']);
										$temp[0] = chr(ASN1::TYPE_SET | 0x20);
										$counterSignerinfo['signedAttrs_raw'] = $temp;
									}

		//							$signerinfo['raw'] = $countersignRaw;
									//var_dump($counterSignerinfo);
									
									$digestBody = $signerInfo['signature'];
									$validation = $this->validateCountersignature($counterSignerinfo,$digestBody,$cms['content']['certificates']);
//									var_dump($validation);
//									$signerinfo['validation']['valid'] = ;
									$counterSignerinfo['validation'] = $validation['validation'];
									//var_dump($counterSignerinfo);
									$unsignedAttr['value'] = $counterSignerinfo;
									
								break;
								
								case "szOID_NESTED_SIGNATURE":
									foreach($unsignedAttr['value'] as $nestedPKCS) {
										$raw = $nestedPKCS->element;
										//hex_dump($raw);
										$this->load($raw);
										//var_dump($this);
									}
								break;
							}
							//var_dump($unsignedAttr['value']['validation']);
						}
				}
				//var_dump($cms['content']['signerInfos']);
				
                $this->currentCMS[] = $cms;
                
                return $cms;
        }
    }
	
	function parseSignedData( $signedData, $dbg=false )
	{
		if($dbg)debug_print_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
		$raw = $signedData;
		$decoded = ASN1::decodeBER($raw);
//		if($dbg)var_dump($decoded);
		// try CMS notation
		$parsed = @ASN1::asn1map($decoded[0],$this->SignedData,$dbg);
		if($parsed===NULL) {	// not CMS, use PKCS7 notation
			$parsed = ASN1::asn1map($decoded[0],$this->SignedDataAuthentiCode,$dbg);
			//contentInfo->content is DER encoded
			if($dbg)var_dump($parsed);
			$parsed['contentInfo']['content_raw'] = substr($parsed['contentInfo']['content']->element,$parsed['contentInfo']['content']->headerLength);
		} else {
			$parsed['encapContentInfo']['eContent_raw'] = $parsed['encapContentInfo']['eContent'];
		}
		
		foreach ($parsed['signerInfos'] as $key => &$signerInfo) {
			if (isset($signerInfo['signedAttrs']) && count($signerInfo['signedAttrs'])) {
				$signerInfoIdx = 3 + isset($parsed['certificates']) + isset($parsed['crls']);
				$asn1desc = $decoded[0]['content'][$signerInfoIdx]['content'][$key]['content'][3];
				$temp = substr($signedData, $asn1desc['start'], $asn1desc['length']);
				$temp[0] = chr(ASN1::TYPE_SET | 0x20);
				$signerInfo['signedAttrs_raw'] = $temp;
			}
		}
		
		if (isset($parsed['certificates'])) {
			foreach ($parsed['certificates'] as $i => $cert) {
				if (isset($cert['certificate'])) {
					$temp = $decoded[0]['content'][3]['content'][$i];
					$rawcert = substr($signedData, $temp['start'], $temp['length']);
					$this->certs['raw'][] = $rawcert;
					$this->certs['parsed'][] = $cert;
					$parsed['certificates_raw'][] = $rawcert;
				}
			}
		}
	
		return ($parsed);
	}
	
	function _findCertBySerial($certs,$serial) {
		foreach($certs as $cert) {
			if(isset($cert['certificate']['tbsCertificate']['serialNumber'])) {
				$curSerial = $cert['certificate']['tbsCertificate']['serialNumber'];
				if($curSerial->equals($serial))
					return $cert;
			} else 
				continue;
		}
		return NULL;
	}
	
	private function validateSignatureHelper( $signatureAlgorithm, $digestAlgorithm, $publicKeyInfo, $verifyBody, $signature, $informal=false ) {
//		var_dump( $signatureAlgorithm, $digestAlgorithm, $publicKeyInfo, $verifyBody, $signature, $informal);
		switch($signatureAlgorithm) {
			case 'rsaEncryption':
			case 'md2WithRSAEncryption':
			case 'md5WithRSAEncryption':
			case 'sha1WithRSAEncryption':
			case 'sha224WithRSAEncryption':
			case 'sha256WithRSAEncryption':
			case 'sha384WithRSAEncryption':
			case 'sha512WithRSAEncryption':
				$publicKey = $publicKeyInfo['subjectPublicKey'];
				//echo("\nkey\n");hex_dump($publicKey);
				$publicKey = substr($publicKey,1);
				
				$rsa = new RSA();
				$rsa->setHash(preg_replace('#^id-#', '', $digestAlgorithm));
				$rsa->load($publicKey);
				if($informal)
					$valid = $rsa->verify($verifyBody,$signature,RSA::PADDING_PKCS1_RAW);
				else
					$valid = $rsa->verify($verifyBody,$signature,RSA::PADDING_PKCS1);
			break;
			
			case 'id-ecPublicKey':		//ECDSA anyway, for old signtool?
				$signatureAlgorithm = "ecdsa-with-".preg_replace('#^id-#', '', $digestAlgorithm);
			case 'ecdsa-with-SHA1':
			case 'ecdsa-with-SHA256':
			case 'ecdsa-with-SHA384':
			case 'ecdsa-with-SHA512':
				$curve = ($publicKeyInfo['algorithm']['parameters']['objectIdentifier']);
				preg_match("/[0-9]+/",$curve,$matches);
				$bits = $matches[0];
				$der = ASN1::encodeDER($publicKeyInfo,Maps\SubjectPublicKeyInfo::MAP);
				
				$generatorFn = "generator".$bits;
				$adapter = \Mdanter\Ecc\EccFactory::getAdapter();
				$generator = \Mdanter\Ecc\EccFactory::getNistCurves()->$generatorFn();
				$sigSerializer = new \Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer();
				$sig = $sigSerializer->parse($signature);
				$derSerializer = new \Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer($adapter);
				//$pemSerializer = new \Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer($derSerializer);
				$key = $derSerializer->parse($der);

				$hasher = new \Mdanter\Ecc\Crypto\Signature\SignHasher(strtolower(preg_replace('#^ecdsa-with-#', '', $signatureAlgorithm)));
				$hash = $hasher->makeHash($verifyBody, $generator);
//				var_dump(gmp_strval($hash,16));
				$signer = new \Mdanter\Ecc\Crypto\Signature\Signer($adapter);
				$valid = $signer->verify($key, $sig, $hash);
			break;
			
			default:
				throw new \RuntimeException("ivnalid signatureAlgorithm");
			break;
		}
		return $valid;
	}
	
	function validateSignedData( &$signedData ) {
		$signedData['validation']['valid'] = true;
		
		if(isset($signedData['encapContentInfo']))
			$messageBody = $signedData['encapContentInfo']['eContent_raw'];
		else
			$messageBody = $signedData['contentInfo']['content_raw'];
			
		$digestAlgo = preg_replace('#^id-#', '', $signedData['digestAlgorithms'][0]['algorithm']);
		$calculatedDigest = hash($digestAlgo,$messageBody);
		
		foreach($signedData['signerInfos'] as $signerInfo) {
			foreach($signerInfo['signedAttrs'] as $signedAttr) {
				if($signedAttr['type']=='id-messageDigest')
					$storedDigest = bin2hex($signedAttr['value'][0]['octetString']);
			}
			
			$signedData['validation']['signedAttrs']['digestAlgorithm'] = $digestAlgo;
			$signedData['validation']['signedAttrs']['storedDigest'] = $storedDigest;
			$signedData['validation']['signedAttrs']['calculatedDigest'] = $calculatedDigest;
			if($calculatedDigest==$storedDigest) {
				$signedData['validation']['signedAttrs']['valid'] = true;
			} else {
				$signedData['validation']['signedAttrs']['valid'] = false;
				$signedData['validation']['valid'] = false;
			}
			
			if(isset($signerInfo['sid']['issuerAndSerialNumber'])) {
				if(isset($signerInfo['sid']['issuerAndSerialNumber']['serialNumber'])) {
					if(($cert=$this->_findCertBySerial($signedData['certificates'],$signerInfo['sid']['issuerAndSerialNumber']['serialNumber']))!==NULL) {
//						var_dump($signerInfo);
						//var_dump($signerInfo['signatureAlgorithm'],$signerInfo['digestAlgorithm'],$cert['certificate']['tbsCertificate']['subjectPublicKeyInfo']);
						
						$verifyBody = $signerInfo['signedAttrs_raw'];
						$signature = $signerInfo['signature'];
						
						$signedData['validation']['signature']['signerInfo']['commonName'] = $this->_getCommonName($cert['certificate']);
						$signedData['validation']['signature']['signerInfo']['serialNumber'] = $cert['certificate']['tbsCertificate']['serialNumber']->toHex();
						$signedData['validation']['signature']['signerInfo']['certificate'] = $cert['certificate'];
						//$signedData['validation']['signature']['raw'] = $signature;
						//$signedData['validation']['signature']['msg'] = $verifyBody;
						//$signedData['validation']['signature']['publickey'] = $publicKey;
						
						$valid = $this->validateSignatureHelper( $signerInfo['signatureAlgorithm']['algorithm'], $signerInfo['digestAlgorithm']['algorithm'], $cert['certificate']['tbsCertificate']['subjectPublicKeyInfo'], $verifyBody, $signature );
						
						if($valid) {
							$signedData['validation']['signature']['valid'] = true;
						} else {
							$signedData['validation']['signature']['valid'] = false;
							$signedData['validation']['valid'] = false;
						}
					} 
				} else {
					var_dump($signerInfo['sid']['issuerAndSerialNumber']);
				}
			}
		}		
	}
	
	function validateCountersignature( $counterSignerInfo, $messageBody, $certificates ) {
//		var_dump($counterSignerInfo);return;
		$digestAlgo = preg_replace('#^id-#', '', $counterSignerInfo['digestAlgorithm']['algorithm']);
		$calculatedDigest = hash($digestAlgo,$messageBody);
	
		foreach($counterSignerInfo['signedAttrs'] as $signedAttr) {
			if($signedAttr['type']=='id-messageDigest')
				$storedDigest = bin2hex($signedAttr['value'][0]['octetString']);
		}
//		var_dump($calculatedDigest,$storedDigest);
		
		$result['validation']['valid'] = true;
		$result['validation']['counterSignature']['digestAlgorithm'] = $digestAlgo;
		$result['validation']['counterSignature']['storedDigest'] = $storedDigest;
		$result['validation']['counterSignature']['calculatedDigest'] = $calculatedDigest;
		if($calculatedDigest==$storedDigest) {
			$result['validation']['counterSignature']['valid'] = true;
		} else {
			$result['validation']['counterSignature']['valid'] = false;
			$result['validation']['valid'] = false;
		}
		
		if(isset($counterSignerInfo['sid']['issuerAndSerialNumber'])) {
			if(isset($counterSignerInfo['sid']['issuerAndSerialNumber']['serialNumber'])) {
				if(($cert=$this->_findCertBySerial($certificates,$counterSignerInfo['sid']['issuerAndSerialNumber']['serialNumber']))!==NULL) {
					//var_dump($cert);
//					$publicKey = $cert['certificate']['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];
//					$publicKey = substr($publicKey,1);
					
//					$rsa = new RSA();
//					$rsa->setHash(preg_replace('#^id-#', '', $counterSignerInfo['digestAlgorithm']['algorithm']));
//					$rsa->load($publicKey);
					$verifyBody = $counterSignerInfo['signedAttrs_raw'];
					$signature = $counterSignerInfo['signature'];
					
					$result['validation']['signature']['signerInfo']['commonName'] = $this->_getCommonName($cert['certificate']);
					$result['validation']['signature']['signerInfo']['serialNumber'] = $cert['certificate']['tbsCertificate']['serialNumber']->toHex();
					$result['validation']['signature']['signerInfo']['certificate'] = $cert['certificate'];
//					$result['validation']['signature']['raw'] = $signature;
//					$result['validation']['signature']['msg'] = $verifyBody;
//					$result['validation']['signature']['publickey'] = $publicKey;
//					echo("\nkey\n");hex_dump($publicKey);
//					echo("\nmsg\n");hex_dump($verifyBody);
//					echo("\nsignature\n");hex_dump(($signature));
					
//					for($i=1;$i<7;$i++)
//						var_dump($rsa->verify($verifyBody,$signature,$i));						
//					exit(0);

					$result['validation']['signature']['informal'] = false;
					$valid = $this->validateSignatureHelper( $counterSignerInfo['signatureAlgorithm']['algorithm'], $counterSignerInfo['digestAlgorithm']['algorithm'], $cert['certificate']['tbsCertificate']['subjectPublicKeyInfo'], $verifyBody, $signature );
					if($valid) {
						$result['validation']['signature']['valid'] = true;
					} else if($valid = $this->validateSignatureHelper( $counterSignerInfo['signatureAlgorithm']['algorithm'], $counterSignerInfo['digestAlgorithm']['algorithm'], $cert['certificate']['tbsCertificate']['subjectPublicKeyInfo'], $verifyBody, $signature, true )) {
						$result['validation']['signature']['valid'] = true;
						$result['validation']['signature']['informal'] = true;
					} else {
						$result['validation']['signature']['valid'] = false;
						$result['validation']['valid'] = false;
					}
				} 
			} else {
				var_dump($signerInfo['sid']['issuerAndSerialNumber']);
			}
		}
		return $result;
	}

    function getCerts()
    {
        return $this->certs;
    }

    function _getSubjectPublicKey($cert)
    {
        if (!isset($cert['tbsCertificate']['extensions'])) {
            return false;
        }
        foreach ($cert['tbsCertificate']['extensions'] as $ext) {
            if ($ext['extnId'] == 'id-ce-subjectKeyIdentifier') {
                return $ext['extnValue'];
            }
        }
        return false;
    }

    function _getCommonName($cert)
    {
        if (!isset($cert['tbsCertificate']['issuer'])) {
            return false;
        }
        foreach ($cert['tbsCertificate']['subject']['rdnSequence'] as $ent) {
			$ent = $ent[0];
            if ($ent['type'] == 'id-at-commonName') {
                return array_pop($ent['value']);
            }
        }
        return false;
    }
}
