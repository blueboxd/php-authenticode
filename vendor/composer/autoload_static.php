<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitf5b711b7955f8d23df053b89bfe9fbb8
{
    public static $files = array (
        '5255c38a0faeba867671b61dfda6d864' => __DIR__ . '/..' . '/paragonie/random_compat/lib/random.php',
        'decc78cc4436b1292c6c0d151b19445c' => __DIR__ . '/..' . '/phpseclib/phpseclib/phpseclib/bootstrap.php',
    );

    public static $prefixLengthsPsr4 = array (
        'p' => 
        array (
            'phpseclib\\' => 10,
        ),
        'P' => 
        array (
            'ParagonIE\\ConstantTime\\' => 23,
        ),
        'M' => 
        array (
            'Mdanter\\Ecc\\' => 12,
        ),
        'K' => 
        array (
            'Kaitai\\' => 7,
        ),
        'F' => 
        array (
            'FG\\' => 3,
        ),
        'A' => 
        array (
            'ASN1\\' => 5,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'phpseclib\\' => 
        array (
            0 => __DIR__ . '/..' . '/phpseclib/phpseclib/phpseclib',
        ),
        'ParagonIE\\ConstantTime\\' => 
        array (
            0 => __DIR__ . '/..' . '/paragonie/constant_time_encoding/src',
        ),
        'Mdanter\\Ecc\\' => 
        array (
            0 => __DIR__ . '/..' . '/mdanter/ecc/src',
        ),
        'Kaitai\\' => 
        array (
            0 => __DIR__ . '/..' . '/kaitai-io/kaitai_struct_php_runtime/lib/Kaitai',
        ),
        'FG\\' => 
        array (
            0 => __DIR__ . '/..' . '/fgrosse/phpasn1/lib',
        ),
        'ASN1\\' => 
        array (
            0 => __DIR__ . '/..' . '/sop/asn1/lib/ASN1',
        ),
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitf5b711b7955f8d23df053b89bfe9fbb8::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitf5b711b7955f8d23df053b89bfe9fbb8::$prefixDirsPsr4;

        }, null, ClassLoader::class);
    }
}
