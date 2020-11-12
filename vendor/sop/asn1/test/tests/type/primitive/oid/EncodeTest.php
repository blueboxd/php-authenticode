<?php

declare(strict_types=1);

use ASN1\Type\Primitive\ObjectIdentifier;

/**
 * @group encode
 * @group oid
 */
class ObjectIdentifierEncodeTest extends PHPUnit_Framework_TestCase
{
    public function testZero()
    {
        $oid = new ObjectIdentifier("0");
        $this->assertEquals("\x6\1\0", $oid->toDER());
    }
    
    public function testEncodeLong()
    {
        $oid = new ObjectIdentifier("1.2.840.113549");
        $this->assertEquals("\x06\x06\x2a\x86\x48\x86\xf7\x0d", $oid->toDER());
    }
}
