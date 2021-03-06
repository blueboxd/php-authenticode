<?php

declare(strict_types = 1);

namespace ASN1\Component;

use ASN1\Exception\DecodeException;
use ASN1\Feature\Encodable;
use ASN1\Util\BigInt;

/**
 * Class to represent BER/DER identifier octets.
 */
class Identifier implements Encodable
{
    // Type class enumerations
    const CLASS_UNIVERSAL = 0b00;
    const CLASS_APPLICATION = 0b01;
    const CLASS_CONTEXT_SPECIFIC = 0b10;
    const CLASS_PRIVATE = 0b11;
    
    /**
     * Mapping from type class to human readable name.
     *
     * @internal
     *
     * @var array
     */
    const MAP_CLASS_TO_NAME = [ /* @formatter:off */
        self::CLASS_UNIVERSAL => "UNIVERSAL", 
        self::CLASS_APPLICATION => "APPLICATION", 
        self::CLASS_CONTEXT_SPECIFIC => "CONTEXT SPECIFIC", 
        self::CLASS_PRIVATE => "PRIVATE",
        /* @formatter:on */
    ];
    
    // P/C enumerations
    const PRIMITIVE = 0b0;
    const CONSTRUCTED = 0b1;
    
    /**
     * Type class.
     *
     * @var int
     */
    private $_class;
    
    /**
     * Primitive or Constructed.
     *
     * @var int
     */
    private $_pc;
    
    /**
     * Content type tag.
     *
     * @var BigInt
     */
    private $_tag;
    
    /**
     * Constructor.
     *
     * @param int $class Type class
     * @param int $pc Primitive / Constructed
     * @param int|string $tag Type tag number
     */
    public function __construct(int $class, int $pc, $tag)
    {
        $this->_class = 0b11 & $class;
        $this->_pc = 0b1 & $pc;
        $this->_tag = new BigInt($tag);
    }
    
    /**
     * Decode identifier component from DER data.
     *
     * @param string $data DER encoded data
     * @param int|null $offset Reference to the variable that contains offset
     *        into the data where to start parsing. Variable is updated to
     *        the offset next to the parsed identifier. If null, start from
     *        offset 0.
     * @throws DecodeException If decoding fails
     * @return self
     */
    public static function fromDER(string $data, int &$offset = null): Identifier
    {
        $idx = $offset ? $offset : 0;
        $datalen = strlen($data);
        if ($idx >= $datalen) {
            throw new DecodeException("Invalid offset.");
        }
        $byte = ord($data[$idx++]);
//		printf("%d:%02x\n",$offset,$byte);
        // bits 8 and 7 (class)
        // 0 = universal, 1 = application, 2 = context-specific, 3 = private
        $class = (0b11000000 & $byte) >> 6;
        // bit 6 (0 = primitive / 1 = constructed)
        $pc = (0b00100000 & $byte) >> 5;
        // bits 5 to 1 (tag number)
        $tag = (0b00011111 & $byte);
        // long-form identifier
//		var_dump($class, $pc, $tag);
        if (0x1f == $tag) {
            $tag = self::_decodeLongFormTag($data, $idx);
        }
        if (isset($offset)) {
            $offset = $idx;
        }
        return new self($class, $pc, $tag);
    }
    
    /**
     * Parse long form tag.
     *
     * @param string $data DER data
     * @param int $offset Reference to the variable containing offset to data
     * @throws DecodeException If decoding fails
     * @return string Tag number
     */
    private static function _decodeLongFormTag(string $data, int &$offset): string
    {
        $datalen = strlen($data);
        $tag = gmp_init(0, 10);
        while (true) {
            if ($offset >= $datalen) {
                throw new DecodeException(
                    "Unexpected end of data while decoding" .
                         " long form identifier.");
            }
            $byte = ord($data[$offset++]);
            $tag <<= 7;
            $tag |= 0x7f & $byte;
            // last byte has bit 8 set to zero
            if (!(0x80 & $byte)) {
                break;
            }
        }
        return gmp_strval($tag, 10);
    }
    
    /**
     *
     * @see Encodable::toDER()
     * @return string
     */
    public function toDER(): string
    {
        $bytes = [];
        $byte = $this->_class << 6 | $this->_pc << 5;
        $tag = $this->_tag->gmpObj();
        if ($tag < 0x1f) {
            $bytes[] = $byte | $tag;
        } else { // long-form identifier
            $bytes[] = $byte | 0x1f;
            $octets = [];
            for (; $tag > 0; $tag >>= 7) {
                array_push($octets, gmp_intval(0x80 | ($tag & 0x7f)));
            }
            // last octet has bit 8 set to zero
            $octets[0] &= 0x7f;
            foreach (array_reverse($octets) as $octet) {
                $bytes[] = $octet;
            }
        }
        return pack("C*", ...$bytes);
    }
    
    /**
     * Get class of the type.
     *
     * @return int
     */
    public function typeClass(): int
    {
        return $this->_class;
    }
    
    /**
     * Get P/C.
     *
     * @return int
     */
    public function pc(): int
    {
        return $this->_pc;
    }
    
    /**
     * Get the tag number.
     *
     * @return string Base 10 integer string
     */
    public function tag(): string
    {
        return $this->_tag->base10();
    }
    
    /**
     * Get the tag as an integer.
     *
     * @return int
     */
    public function intTag(): int
    {
        return $this->_tag->intVal();
    }
    
    /**
     * Check whether type is of an universal class.
     *
     * @return boolean
     */
    public function isUniversal(): bool
    {
        return self::CLASS_UNIVERSAL == $this->_class;
    }
    
    /**
     * Check whether type is of an application class.
     *
     * @return boolean
     */
    public function isApplication(): bool
    {
        return self::CLASS_APPLICATION == $this->_class;
    }
    
    /**
     * Check whether type is of a context specific class.
     *
     * @return boolean
     */
    public function isContextSpecific(): bool
    {
        return self::CLASS_CONTEXT_SPECIFIC == $this->_class;
    }
    
    /**
     * Check whether type is of a private class.
     *
     * @return boolean
     */
    public function isPrivate(): bool
    {
        return self::CLASS_PRIVATE == $this->_class;
    }
    
    /**
     * Check whether content is primitive type.
     *
     * @return boolean
     */
    public function isPrimitive(): bool
    {
        return self::PRIMITIVE == $this->_pc;
    }
    
    /**
     * Check hether content is constructed type.
     *
     * @return boolean
     */
    public function isConstructed(): bool
    {
        return self::CONSTRUCTED == $this->_pc;
    }
    
    /**
     * Get self with given type class.
     *
     * @param int $class One of <code>CLASS_*</code> enumerations
     * @return self
     */
    public function withClass(int $class): Identifier
    {
        $obj = clone $this;
        $obj->_class = $class;
        return $obj;
    }
    
    /**
     * Get self with given type tag.
     *
     * @param int|string $tag Tag number
     * @return self
     */
    public function withTag($tag): Identifier
    {
        $obj = clone $this;
        $obj->_tag = new BigInt($tag);
        return $obj;
    }
    
    /**
     * Get human readable name of the type class.
     *
     * @param int $class
     * @return string
     */
    public static function classToName(int $class): string
    {
        if (!array_key_exists($class, self::MAP_CLASS_TO_NAME)) {
            return "CLASS $class";
        }
        return self::MAP_CLASS_TO_NAME[$class];
    }
}
