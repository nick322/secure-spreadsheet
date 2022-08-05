<?php

namespace Nick\SecureSpreadsheet;

class CFB
{
    public function cfb_new($opts = null)
    {
        $o = new \stdClass();
        $this->init_cfb($o, $opts);
        return $o;
    }

    public function cfb_add(&$cfb, $name, $content, $opts = null)
    {
        $unsafe = $opts && $opts->unsafe;
        if (!$unsafe) $this->init_cfb($cfb);
        $file = !$unsafe && $this->find($cfb, $name);
        if (!$file) {
            $fpath = $cfb->FullPaths[0];
            if (substr($name, 0, strlen($fpath)) == $fpath) $fpath = $name;
            else {
                if (substr($fpath, -1) != "/") $fpath .= "/";
                $fpath = str_replace("//", "/", $fpath . $name);
            }
            $file = (['name' => $this->filename($name), 'type' => 2]);
            $file['content'] = ($content);
            $file['size'] = $content ? count($content) : 0;

            if ($opts) {
                if ($opts->CLSID) $file['clsid'] = $opts->CLSID;
                if ($opts->mt) $file['mt'] = $opts->mt;
                if ($opts->ct) $file['ct'] = $opts->ct;
            }

            $cfb->FileIndex[] = ($file);
            $cfb->FullPaths[] = ($fpath);
            if (!$unsafe) $this->cfb_gc($cfb);
        }

        return $file;
    }

    private function init_cfb(&$cfb, $opts = null)
    {
        $o = $opts ?? new \stdClass();
        $root = $o->root ?? "Root Entry";
        if (!isset($cfb->FullPaths)) $cfb->FullPaths = [];
        if (!isset($cfb->FileIndex)) $cfb->FileIndex = [];
        if (count($cfb->FullPaths) !== count($cfb->FileIndex)) throw new \Error("inconsistent CFB structure");
        if (count($cfb->FullPaths) === 0) {
            $cfb->FullPaths[0] = $root . "/";
            $cfb->FileIndex[0] = (['name' => $root, 'type' => 5]);
        }
        if (isset($o->CLSID)) $cfb->FileIndex[0]->clsid = $o->CLSID;
        $this->seed_cfb($cfb);
    }

    private function seed_cfb(&$cfb)
    {
        $nm = "\x01Sh33tJ5";
        if ($this->find($cfb, "/" . $nm)) return;
        $p = $this->new_buf(4);
        $p[0] = 55;
        $p[1] = $p[3] = 50;
        $p[2] = 54;
        $cfb->FileIndex[] = ((['name' => $nm, 'type' => 2, 'content' => $p, 'size' => 4, 'L' => 69, 'R' => 69, 'C' => 69]));
        $cfb->FullPaths[] = ($cfb->FullPaths[0] . $nm);

        $this->rebuild_cfb($cfb);
    }

    private function new_buf($sz): Buffer
    {
        $o = ($this->new_raw_buf($sz));
        $this->prep_blob($o, 0);
        return $o;
    }

    private function new_raw_buf($sz)
    {
        return new Buffer($sz);
    }

    private function prep_blob($blob, $pos)
    {
        $blob->l = $pos;
    }

    private function cfb_gc(&$cfb)
    {
        $this->rebuild_cfb($cfb, true);
    }

    private function rebuild_cfb(&$cfb, $f = false)
    {
        $HEADER_CLSID = '00000000000000000000000000000000';

        $this->init_cfb($cfb);
        $gc = false;
        $s = false;
        for ($i = count($cfb->FullPaths) - 1; $i >= 0; --$i) {
            $_file = $cfb->FileIndex[$i];
            // var_dump($_file);
            switch ($_file['type']) {
                case 0:
                    if ($s) $gc = true;
                    else {
                        array_pop($cfb->FileIndex);
                        array_pop($cfb->FullPaths);
                    }
                    break;
                case 1:
                case 2:
                case 5:
                    $s = true;
                    if (!isset($_file['R'], $_file['L'], $_file['C'])) $gc = true;
                    if (isset($_file['R'], $_file['L'], $_file['C']) && $_file['R'] > -1 && $_file['L'] > -1 && $_file['R'] == $_file['L']) $gc = true;
                    break;
                default:
                    $gc = true;
                    break;
            }
        }
        if (!$gc && !$f) return;

        $now = mktime(0, 0, 0, 1, 19, 1987);
        $j = 0;
        // Track which names exist
        $fullPaths = [];
        $data = [];
        for ($i = 0; $i < count($cfb->FullPaths); ++$i) {
            $fullPaths[$cfb->FullPaths[$i]] = true;
            if ($cfb->FileIndex[$i]['type'] === 0) continue;
            $data[] = ([$cfb->FullPaths[$i], $cfb->FileIndex[$i]]);
        }
        for ($i = 0; $i < count($data); ++$i) {
            $dad = $this->dirname($data[$i][0]);

            $s = $fullPaths[$dad];
            while (!$s) {
                while ($this->dirname($dad) && !$fullPaths[$this->dirname($dad)]) $dad =  $this->dirname($dad);

                $data[] = ([$dad, ([
                    'name' => str_replace("/", "", $this->filename($dad)),
                    'type' => 1,
                    'clsid' => $HEADER_CLSID,
                    'ct' => $now, 'mt' => $now,
                    'content' => null
                ])]);

                // Add name to set
                $fullPaths[$dad] = true;

                $dad = dirname($data[$i][0]);
                $s = $fullPaths[$dad];
            }
        }
        usort($data, array(Self::class, "namecmp"));

        $cfb->FullPaths = [];
        $cfb->FileIndex = [];
        for ($i = 0; $i < count($data); ++$i) {
            $cfb->FullPaths[$i] = $data[$i][0];
            $cfb->FileIndex[$i] = $data[$i][1];
        }
        for ($i = 0; $i < count($data); ++$i) {
            $elt = $cfb->FileIndex[$i];
            $nm = $cfb->FullPaths[$i];

            // $elt['name'] = $nm;
            $elt['name'] =  str_replace("/", "", $this->filename($nm));
            $elt['L'] = $elt['R'] = $elt['C'] = - ($elt['color'] = 1);
            if (isset($elt['content'])) {
                $elt['size'] = $elt['content'] ? count($elt['content']) : 0;
            } else {
                $elt['size'] = 0;
            }
            $elt['start'] = 0;
            $elt['clsid'] = ($elt['clsid'] ?? $HEADER_CLSID);
            if ($i === 0) {
                $elt['C'] = count($data) > 1 ? 1 : -1;
                $elt['size'] = 0;
                $elt['type'] = 5;
            } else if (substr($nm, -1) == "/") {
                for ($j = $i + 1; $j < count($data); ++$j) if ($this->dirname($cfb->FullPaths[$j]) == $nm) break;
                $elt['C'] = $j >= count($data) ? -1 : $j;
                for ($j = $i + 1; $j < count($data); ++$j) if ($this->dirname($cfb->FullPaths[$j]) == $this->dirname($nm)) break;
                $elt['R'] = $j >= count($data) ? -1 : $j;
                $elt['type'] = 1;
            } else {
                if ($this->dirname($cfb->FullPaths[$i + 1] ?? "") == $this->dirname($nm)) $elt['R'] = $i + 1;
                $elt['type'] = 2;
            }

            $cfb->FileIndex[$i] = $elt;
            $cfb->FullPaths[$i] = $nm;
        }
        // var_dump($cfb);
    }

    private function find($cfb, $path)
    {
        $UCFullPaths = array_map(function ($i) {
            return strtoupper($i);
        }, $cfb->FullPaths);
        $UCPaths = array_map(function ($i) {
            $y = explode("/", $i);
            return $y[count($y) - (substr($i, -1) == "/" ? 2 : 1)];
        }, $UCFullPaths);

        $k = false;
        if (ord($path[0]) === 47 /* "/" */) {
            $k = true;
            $path = substr($UCFullPaths[0], 0, -1) . $path;
        } else $k = strpos($path, '/') != false;
        $UCPath = strtoupper($path);
        $w = $k === true ? array_search($UCPath, $UCFullPaths) : array_search($UCPath, $UCPaths);
        if ($w > -1) return $cfb->FileIndex[$w];


        return false;
    }

    private static function namecmp($l, $r)
    {
        $L = explode('/', $l[0]);
        $R = explode('/', $r[0]);
        $c = 0;
        $Z = min(count($L), count($R));
        for ($i = 0; $i < $Z; ++$i) {
            if (($c = strlen($L[$i]) - strlen($R[$i]))) return $c;
            if ($L[$i] != $R[$i]) return $L[$i] < $R[$i] ? -1 : 1;
        }
        return count($L) - count($R);
    }

    private function dirname($p)
    {
        $pl = strlen($p);
        if ($pl == 0) {
            return $p;
        }
        if ($p[($pl - 1)] == "/") {
            if ((strpos(substr($p, 0, -1), '/') === false)) {
                return $p;
            }
            return $this->dirname(substr($p, 0, -1));
        }
        $c = strrpos($p, '/');
        return ($c === false) ? $p : substr($p, 0, $c + 1);
    }

    private function filename($p)
    {
        if ($p[(strlen($p) - 1)] == "/") {
            return $this->filename(substr($p, 0, -1));
        }
        $c = strrpos($p, '/');
        return ($c === false) ? $p : substr($p, $c + 1);
    }

    public function write(&$cfb)
    {
        return $this->_write($cfb);
    }


    private function _write(&$cfb)
    {
        $HEADER_SIG = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        $ENDOFCHAIN = -2;

        $this->rebuild_cfb($cfb);

        $L = (function ($cfb) {
            $mini_size = 0;
            $fat_size = 0;
            for ($i = 0; $i < count($cfb->FileIndex); ++$i) {
                $file = $cfb->FileIndex[$i];
                if (!isset($file['content'])) continue;
                $flen = count($file['content']);

                if ($flen > 0) {
                    if ($flen < 0x1000) {
                        $mini_size += ($flen + 0x3F) >> 6;
                    } else {
                        $fat_size += ($flen + 0x01FF) >> 9;
                    }
                }
            }
            $dir_cnt = (count($cfb->FullPaths) + 3) >> 2;
            $mini_cnt = ($mini_size + 7) >> 3;
            $mfat_cnt = ($mini_size + 0x7F) >> 7;
            $fat_base = $mini_cnt + $fat_size + $dir_cnt + $mfat_cnt;
            $fat_cnt = ($fat_base + 0x7F) >> 7;
            $difat_cnt = $fat_cnt <= 109 ? 0 : ceil(($fat_cnt - 109) / 0x7F);
            while ((($fat_base + $fat_cnt + $difat_cnt + 0x7F) >> 7) > $fat_cnt) $difat_cnt = ++$fat_cnt <= 109 ? 0 : ceil(($fat_cnt - 109) / 0x7F);
            $L =  [1, $difat_cnt, $fat_cnt, $mfat_cnt, $dir_cnt, $fat_size, $mini_size, 0];
            $cfb->FileIndex[0]['size'] = $mini_size << 6;
            $L[7] = ($cfb->FileIndex[0]['start'] = $L[0] + $L[1] + $L[2] + $L[3] + $L[4] + $L[5]) + (($L[6] + 7) >> 3);
            return $L;
        })($cfb);
        $o = $this->new_buf($L[7] << 9);
        $i = 0;
        $T = 0; {
            for ($i = 0; $i < 8; ++$i) $o->write_shift(1, $HEADER_SIG[$i]);
            for ($i = 0; $i < 8; ++$i) $o->write_shift(2, 0);
            $o->write_shift(2, 0x003E);
            $o->write_shift(2, 0x0003);
            $o->write_shift(2, 0xFFFE);
            $o->write_shift(2, 0x0009);
            $o->write_shift(2, 0x0006); // 34
            for ($i = 0; $i < 3; ++$i) $o->write_shift(2, 0); // 37
            $o->write_shift(4, 0);
            $o->write_shift(4, $L[2]);
            $o->write_shift(4, $L[0] + $L[1] + $L[2] + $L[3] - 1);
            $o->write_shift(4, 0);
            $o->write_shift(4, 1 << 12);
            $o->write_shift(4, $L[3] ? $L[0] + $L[1] + $L[2] - 1 : $ENDOFCHAIN);
            $o->write_shift(4, $L[3]);
            $o->write_shift(-4, $L[1] ? $L[0] - 1 : $ENDOFCHAIN);
            $o->write_shift(4, $L[1]);
            for ($i = 0; $i < 109; ++$i) $o->write_shift(-4, $i < $L[2] ? $L[1] + $i : -1);
        }

        if ($L[1]) {
            for ($T = 0; $T < $L[1]; ++$T) {
                for (; $i < 236 + $T * 127; ++$i) $o->write_shift(-4, $i < $L[2] ? $L[1] + $i : -1);
                $o->write_shift(-4, $T === $L[1] - 1 ? $ENDOFCHAIN : $T + 1);
            }
        }
        $chainit = function ($w, &$T, &$i, &$o) {
            for ($T += $w; $i < $T - 1; ++$i) $o->write_shift(-4, $i + 1);
            if ($w) {
                ++$i;
                $o->write_shift(-4, -2);
            }
        };
        $T = $i = 0;
        for ($T += $L[1]; $i < $T; ++$i) $o->write_shift(-4, -4);
        for ($T += $L[2]; $i < $T; ++$i) $o->write_shift(-4, -3);
        $chainit($L[3], $T, $i, $o);
        $chainit($L[4], $T, $i, $o);


        $j = 0;
        $flen = 0;
        $file = $cfb->FileIndex[0];
        for (; $j < count($cfb->FileIndex); ++$j) {
            $file = $cfb->FileIndex[$j];
            if (!isset($file['content'])) continue;
            $flen = count($file['content']);
            if ($flen < 0x1000) continue;
            $cfb->FileIndex[$j]['start'] = $T;
            $chainit(($flen + 0x01FF) >> 9, $T, $i, $o);
        }
        $chainit(($L[6] + 7) >> 3, $T, $i, $o);
        while ($o->l & 0x1FF) $o->write_shift(-4, $ENDOFCHAIN);


        $T = $i = 0;
        for ($j = 0; $j < count($cfb->FileIndex); ++$j) {
            $file = $cfb->FileIndex[$j];
            if (!isset($file['content'])) continue;
            $flen = count($file['content']);
            if (!$flen || $flen >= 0x1000) continue;
            $cfb->FileIndex[$j]['start'] = $T;
            $chainit(($flen + 0x3F) >> 6, $T, $i, $o);
        }

        while ($o->l & 0x1FF) $o->write_shift(-4, $ENDOFCHAIN);
        for ($i = 0; $i < $L[4] << 2; ++$i) {
            $nm = $cfb->FullPaths[$i];
            if (!$nm || strlen($nm) === 0) {
                for ($j = 0; $j < 17; ++$j) $o->write_shift(4, 0);
                for ($j = 0; $j < 3; ++$j) $o->write_shift(4, -1);
                for ($j = 0; $j < 12; ++$j) $o->write_shift(4, 0);
                continue;
            }

            $file = $cfb->FileIndex[$i];
            if ($i === 0) {
                $file['start'] = $cfb->FileIndex[$i]['size'] ? ($cfb->FileIndex[$i]['start'] - 1) : $ENDOFCHAIN;
            }
            $_nm = $file['name'];
            if (strlen($_nm) > 32) {
                $_nm = substr($_nm, 0, 32);
            }
            $flen = 2 * (strlen($_nm) + 1);
            $o->write_shift(64, $_nm, "utf16le");
            $o->write_shift(2, $flen);
            $o->write_shift(1, $file['type']);
            $o->write_shift(1, $file['color']);
            $o->write_shift(-4, $file['L']);
            $o->write_shift(-4, $file['R']);
            $o->write_shift(-4, $file['C']);
            if (!$file['clsid']) for ($j = 0; $j < 4; ++$j) $o->write_shift(4, 0);
            else $o->write_shift(16, $file['clsid'], "hex");
            $o->write_shift(4, $file['state'] ?? 0);
            $o->write_shift(4, 0);
            $o->write_shift(4, 0);
            $o->write_shift(4, 0);
            $o->write_shift(4, 0);
            $o->write_shift(4, $file['start']);
            $o->write_shift(4, $file['size']);
            $o->write_shift(4, 0);
        }

        for ($i = 1; $i < count($cfb->FileIndex); ++$i) {
            $file = $cfb->FileIndex[$i];
            if ($file['size'] >= 0x1000) {
                $o->l = ($file['start'] + 1) << 9;

                for ($j = 0; $j < $file['size']; ++$j) $o->write_shift(1, $file['content'][$j]);
                for (; $j & 0x1FF; ++$j) $o->write_shift(1, 0);
            }
        }


        for ($i = 1; $i < count($cfb->FileIndex); ++$i) {
            $file = $cfb->FileIndex[$i];
            if ($file['size'] > 0 && $file['size'] < 0x1000) {
                for ($j = 0; $j < $file['size']; ++$j) $o->write_shift(1, $file['content'][$j]);
                for (; $j & 0x3F; ++$j) $o->write_shift(1, 0);
            }
        }

        while ($o->l < count($o)) $o->write_shift(1, 0);

        return $o;
    }
}
