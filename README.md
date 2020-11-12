# php-authenticode

## What is this?

~~prototype of~~ pure-php implementation of authenticode verifier.

## implemented validation
- authenticode hash (PE32/PE32+)
- signedData integrity
- timestamping (simple countersignature/RFC 3161)
- certificate chain engine with validation:
 - signature (RSA/ECDSA with SHA-1/2)
 - validity period
 - keyUsage/extKeyUsage
 - basicConstraints (CA)

## usage
### simple validation from PHP
```php
require_once "Authenticode.php";

$acVerifier = new Authenticode($pathToPE);
var_dump($acVerifier->isValid());
```

### manual validation
```shell
php tools/verifyAC.php /path/to/PE
```

### certificate store
certificates (pem format) in `trusted/codesigning` are trusted as root CA  
(TBW)

## TODOs

### CCE/w validation
- [ ] CRL validation
 - [ ] CRL loader
 - [x] CRL parser/validator
 - [ ] validate certificate with CRL
- [ ] OCSP support
 - [ ] OCSP client
 - [ ] validate certificate with OCSP result
- [ ] basicConstraints (pathlen)
- [ ] restrict CA certificates for usage