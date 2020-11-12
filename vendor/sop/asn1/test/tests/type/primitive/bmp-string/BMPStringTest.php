<?php

declare(strict_types=1);

use ASN1\Element;
use ASN1\Type\UnspecifiedType;
use ASN1\Type\Primitive\BMPString;
use ASN1\Type\Primitive\NullType;

/**
 * @group type
 * @group bmp-string
 */
class BMPStringTest extends PHPUnit_Framework_TestCase
{
    public function testCreate()
    {
        $el = new BMPString("");
        $this->assertInstanceOf(BMPString::class, $el);
        return $el;
    }
    
    /**
     * @depends testCreate
     *
     * @param Element $el
     */
    public function testTag(Element $el)
    {
        $this->assertEquals(Element::TYPE_BMP_STRING, $el->tag());
    }
    
    /**
     * @depends testCreate
     *
     * @param Element $el
     * @return string
     */
    public function testEncode(Element $el): string
    {
        $der = $el->toDER();
        $this->assertInternalType("string", $der);
        return $der;
    }
    
    /**
     * @depends testEncode
     *
     * @param string $data
     * @return BMPString
     */
    public function testDecode(string $data): BMPString
    {
        $el = BMPString::fromDER($data);
        $this->assertInstanceOf(BMPString::class, $el);
        return $el;
    }
    
    /**
     * @depends testCreate
     * @depends testDecode
     *
     * @param Element $ref
     * @param Element $el
     */
    public function testRecoded(Element $ref, Element $el)
    {
        $this->assertEquals($ref, $el);
    }
    
    /**
     * @depends testCreate
     *
     * @param Element $el
     */
    public function testWrapped(Element $el)
    {
        $wrap = new UnspecifiedType($el);
        $this->assertInstanceOf(BMPString::class, $wrap->asBMPString());
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testWrappedFail()
    {
        $wrap = new UnspecifiedType(new NullType());
        $wrap->asBMPString();
    }
}
