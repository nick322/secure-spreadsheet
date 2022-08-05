<?php

namespace Nick\SecureSpreadsheet;

class Buffer implements \ArrayAccess, \Countable, \Iterator
{
    private $position = 0;
    private $container = [];

    public function __construct($sz)
    {
        $this->position = 0;
        $this->container = array_fill(0, $sz, 0);
    }

    public function offsetSet($offset,  $value): void
    {
        if (is_null($offset)) {
            $this->container[] = $value;
        } else {
            $this->container[$offset] = $value;
        }
    }

    public function offsetExists($offset): bool
    {
        return isset($this->container[$offset]);
    }

    public function offsetUnset($offset): void
    {
        unset($this->container[$offset]);
    }

    #[\ReturnTypeWillChange]
    public function offsetGet($offset)
    {
        return isset($this->container[$offset]) ? $this->container[$offset] : null;
    }

    public function count(): int
    {
        return count($this->container);
    }

    public function __call($name, $arguments)
    {
        return call_user_func($this->{$name}, $arguments);
    }

    public function write_shift($t, $val, $f = '')
    {
        $size = 0;
        $i = 0;
        switch ($f) {
            case "hex":
                for (; $i < $t; ++$i) {
                    $this[$this->l++] = (int) substr($val, 2 * $i, 2);
                }
                return $this;
            case "utf16le":
                $end = $this->l + $t;
                for ($i = 0; $i < min(strlen($val), $t); ++$i) {
                    $string = mb_substr($val, $i, 1);
                    list(, $ret) = unpack('S', mb_convert_encoding($string, 'UTF-16LE'));
                    $cc = $ret;
                    $this[$this->l++] = $cc & 0xff;
                    $this[$this->l++] = $cc >> 8;
                }
                while ($this->l < $end) $this[$this->l++] = 0;
                return $this;
        }
        switch ($t) {
            case  1:
                $size = 1;
                $this[$this->l] = $val & 0xFF;
                break;
            case  2:
                $size = 2;
                $this[$this->l] = $val & 0xFF;
                $val = $this->uRShift($val, 8);
                $this[$this->l + 1] = $val & 0xFF;
                break;
            case  4:
                $size = 4;
                $this->__writeUInt32LE($this, $val, $this->l);
                break;
            case -4:
                $size = 4;
                $this->__writeInt32LE($this, $val, $this->l);
                break;
        }
        $this->l += $size;
        return $this;
    }

    function __writeUInt32LE($b, $val, $idx)
    {
        $b[$idx] = ($val & 0xFF);
        $b[$idx + 1] = ($this->uRShift($val, 8) & 0xFF);
        $b[$idx + 2] = ($this->uRShift($val, 16) & 0xFF);
        $b[$idx + 3] = ($this->uRShift($val, 24) & 0xFF);
    }
    
    function __writeInt32LE($b, $val, $idx)
    {
        $b[$idx] = ($val & 0xFF);
        $b[$idx + 1] = ($val >> 8 & 0xFF);
        $b[$idx + 2] = ($val >> 16 & 0xFF);
        $b[$idx + 3] = ($val >> 24 & 0xFF);
    }

    function uRShift($a, $b)
    {
        if ($b == 0) return $a;
        return ($a >> $b) & ~(1 << (8 * PHP_INT_SIZE - 1) >> ($b - 1));
    }

    #[\ReturnTypeWillChange]
    public function current()
    {
        return $this->container[$this->position];
    }

    #[\ReturnTypeWillChange]
    public function key()
    {
        return $this->position;
    }

    public function next(): void
    {
        ++$this->position;
    }

    public function rewind(): void
    {
        $this->position = 0;
    }

    public function valid(): bool
    {
        return isset($this->container[$this->position]);
    }
}
