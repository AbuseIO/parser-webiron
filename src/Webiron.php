<?php

namespace AbuseIO\Parsers;

use ReflectionClass;
use Log;

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
        $this->configBase = 'parsers.' . $reflect->getShortName();

        Log::info(
            get_class($this). ': Received message from: '.
            $this->parsedMail->getHeader('from') . " with subject: '" .
            $this->parsedMail->getHeader('subject') . "' arrived at parser: " .
            config("{$this->configBase}.parser.name")
        );

        // Define array where all events are going to be saved in.
        $events = [ ];

        /**
         *  Try to find ARF report.
         *  Some notification emails do not contain an ARF report. Instead they
         *  contain a 'table row'-ish with abuse info. In that case we jump down
         *  and parse the email body.
         */
        foreach ($this->parsedMail->getAttachments() as $attachment) {
            // Only use the Webiron formatted reports, skip all others
            if (!preg_match(config("{$this->configBase}.parser.report_file"), $attachment->filename)) {
                $raw_report = $attachment->getContent();
                break;
            }
        }

        // We found an ARF report, yay!
        if (!empty($raw_report)) {
            preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/', $raw_report, $match);
            $report = array_combine($match[1], array_map('trim', $match[2]));
            if (empty($report['Report-Type'])) {
                return $this->failed(
                    "Unabled to detect feed because of required field Report-Type is missing"
                );
            }

            $feedName = $report['Report-Type'];

            // If feed is known and enabled, validate data and save report
            if ($this->isKnownFeed($feedName) && $this->isEnabledFeed($feedName)) {
                // Sanity checks (skip if required fields are unset)
                if ($this->hasRequiredFields($feedName, $report) === true) {
                    $events[] = [
                        'source'        => config("{$this->configBase}.parser.name"),
                        'ip'            => $report['Source'],
                        'domain'        => false,
                        'uri'           => false,
                        'class'         => config("{$this->configBase}.feeds.{$feedName}.class"),
                        'type'          => config("{$this->configBase}.feeds.{$feedName}.type"),
                        'timestamp'     => strtotime(str_replace('\'', '', $report['Date'])),
                        'information'   => json_encode($report),
                    ];
                } else {
                    return $this->failed(
                        "Required field {$this->requiredField} is missing in the report or config is incorrect."
                    );
                }
            } else {
                return $this->failed(
                    "Detected feed '{$feedName}' is unknown or disabled."
                );
            }

        } else {
            // Didn't find an ARF report, go scrape the email body!
            $body = $this->parsedMail->getMessageBody();
            $feedName = 'botnet-infection';

            preg_match_all('/  - ([^:]+): ([^\n]+)\n/', $body, $match);
            $report = array_combine($match[1], array_map('trim', $match[2]));

            // Get IP address
            preg_match('/Offending\/Source IP:[ ]+([0-9\.]+)\n/', $body, $match);
            $report['Source'] = $match[1];

            // If feed is known and enabled, validate data and save report
            if ($this->isKnownFeed($feedName) && $this->isEnabledFeed($feedName)) {
                // Sanity checks (skip if required fields are unset)
                if ($this->hasRequiredFields($feedName, $report) === true) {
                    $events[] = [
                        'source'        => config("{$this->configBase}.parser.name"),
                        'ip'            => $report['Source'],
                        'domain'        => false,
                        'uri'           => false,
                        'class'         => config("{$this->configBase}.feeds.{$feedName}.class"),
                        'type'          => config("{$this->configBase}.feeds.{$feedName}.type"),
                        'timestamp'     => strtotime($report['Time']),
                        'information'   => json_encode($report),
                    ];
                }
            }
        }

        return $this->success($events);
    }
}
