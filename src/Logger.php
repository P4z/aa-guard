<?php

declare(strict_types=1);

namespace AAGuard;

final class Logger
{
    /** @var null|callable(string, string):void */
    private $logForwarder;

    /**
     * @param null|callable(string, string):void $logForwarder
     */
    public function __construct(?callable $logForwarder = null)
    {
        $this->logForwarder = $logForwarder;
    }

    public function debug(string $message): void
    {
        $this->write('DEBUG', $message);
    }

    public function warning(string $message): void
    {
        $this->write('WARN', $message);
    }

    public function error(string $message): void
    {
        $this->write('ERROR', $message);
    }

    private function write(string $level, string $message): void
    {
        if ($this->logForwarder !== null) {
            ($this->logForwarder)($level, $message);
        }

        fwrite(STDERR, sprintf("[%s] %s %s\n", date('c'), $level, $message));
    }
}
