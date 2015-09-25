<?php

namespace AbuseIO\Parsers;

use Ddeboer\DataImport\Reader;
use Ddeboer\DataImport\Writer;
use Ddeboer\DataImport\Filter;
use Illuminate\Filesystem\Filesystem;
use SplFileObject;
use Uuid;
use Log;
use ReflectionClass;

class Webiron extends Parser
{
    public $parsedMail;
    public $arfMail;

    /**
     * Create a new Webiron instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        $this->parsedMail = $parsedMail;
        $this->arfMail = $arfMail;
    }

    /**
     * Parse attachments
     * @return Array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        // Generalize the local config based on the parser class name.
        $reflect = new ReflectionClass($this);
        $configBase = 'parsers.' . $reflect->getShortName();

        Log::info(
            get_class($this). ': Received message from: '.
            $this->parsedMail->getHeader('from') . " with subject: '" .
            $this->parsedMail->getHeader('subject') . "' arrived at parser: " .
            config("{$configBase}.parser.name")
        );

        $events = [ ];

        foreach ($this->parsedMail->getAttachments() as $attachment) {
            // Only use the Webiron formatted reports, skip all others
            // Format described here: https://www.webiron.com/arf/malware-attack.json
            if (!preg_match(config("{$configBase}.parser.report_file"), $attachment->filename)) {
                continue;
            }

            $tempUUID = Uuid::generate(4);
            $tempPath = "/tmp/${tempUUID}/";
            $filesystem = new Filesystem;

            if (!$filesystem->makeDirectory($tempPath)) {
                return $this->failed("Unable to create directory ${tempPath}");
            }

            file_put_contents($tempPath . $attachment->filename, $attachment->getContent());
            $report = $attachment->getContent();

            preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/', $report, $match);
            $row = array_combine($match[1], array_map('trim', $match[2]));

            if (empty($row['Report-Type'])) {
                return $this->failed(
                    "Unabled to detect feed because of required field Report-Type is missing"
                );
            }

            $feedName = $row['Report-Type'];

            if (empty(config("{$configBase}.feeds.{$feedName}"))) {
                $filesystem->deleteDirectory($tempPath);
                return $this->failed(
                    "Detected feed '{$feedName}' is unknown."
                );
            }

            if (config("{$configBase}.feeds.{$feedName}.enabled") !== true) {
                continue;
            }

            $columns = array_filter(config("{$configBase}.feeds.{$feedName}.fields"));
            if (count($columns) > 0) {
                foreach ($columns as $column) {
                    if (!isset($row[$column])) {
                        return $this->failed(
                            "Required field ${column} is missing in the report or config is incorrect."
                        );
                    }
                }
            }

            $event = [
                'source'        => config("{$configBase}.parser.name"),
                'ip'            => $row['Source'],
                'domain'        => false,
                'uri'           => false,
                'class'         => config("{$configBase}.feeds.{$feedName}.class"),
                'type'          => config("{$configBase}.feeds.{$feedName}.type"),
                'timestamp'     => strtotime(str_replace('\'', '', $row['Date'])),
                'information'   => json_encode($row),
            ];

            $events[] = $event;
            $filesystem->deleteDirectory($tempPath);
        }

        return $this->success($events);
    }
}
