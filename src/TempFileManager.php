<?php

namespace Nick\SecureSpreadsheet;

use RuntimeException;

class TempFileManager
{
    private $baseDir;

    private $jobDir;

    private $cleaned = false;

    public function __construct(?string $preferredDir = null)
    {
        $this->baseDir = $this->resolveBaseDir($preferredDir);
        $this->jobDir = $this->createJobDir();

        // request shutdown function to cleanup temp files
        register_shutdown_function([$this, 'cleanup']);
    }

    private function resolveBaseDir(?string $preferredDir): string
    {
        $candidates = array_filter([
            $preferredDir,
            getenv('TMPDIR'),
            getenv('TMP'),
            getenv('TEMP'),
            sys_get_temp_dir(),
            '/tmp',
            getcwd().DIRECTORY_SEPARATOR.'tmp',
        ]);

        foreach ($candidates as $dir) {
            if ($this->isUsableDir($dir)) {
                return rtrim($dir, DIRECTORY_SEPARATOR);
            }
        }

        throw new RuntimeException('No usable temp directory.');
    }

    private function isUsableDir(string $dir): bool
    {
        return is_dir($dir)
            && is_writable($dir)
            && ! is_link($dir);
    }

    private function createJobDir(): string
    {
        $jobDir = $this->baseDir.DIRECTORY_SEPARATOR.'job_'.bin2hex(random_bytes(8));

        if (! mkdir($jobDir, 0700)) {
            throw new RuntimeException('Failed to create job temp directory');
        }

        return $jobDir;
    }

    public function path(string $name): string
    {
        return $this->jobDir.DIRECTORY_SEPARATOR.$name;
    }

    public function cleanup(): void
    {
        if ($this->cleaned || ! is_dir($this->jobDir)) {
            return;
        }

        $files = glob($this->jobDir.DIRECTORY_SEPARATOR.'*') ?: [];
        foreach ($files as $file) {
            @unlink($file);
        }

        @rmdir($this->jobDir);
        $this->cleaned = true;
    }
}
