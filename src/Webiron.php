<?php

namespace AbuseIO\Parsers;

use ReflectionClass;
use Log;

class Webiron extends Parser
{
    /**
     * Create a new Webiron instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail);
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

        /**
         *  Try to find ARF report.
         *  Some notification emails do not contain an ARF report. Instead they
         *  contain a 'table row'-ish with abuse info. In that case we jump down
         *  and parse the email body.
         */
        $foundArf = false;
        foreach ($this->parsedMail->getAttachments() as $attachment) {
            // Only use the Webiron formatted reports, skip all others
            if (preg_match(config("{$this->configBase}.parser.report_file"), $attachment->filename)) {
                $raw_report = $attachment->getContent();

                // We found an ARF report, yay!
                if (!empty($raw_report)) {
                    $foundArf = true;

                    preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/', $raw_report, $matches);
                    $report = array_combine($matches[1], array_map('trim', $matches[2]));

                    if (!empty($report['Report-Type'])) {
                        $this->feedName = $report['Report-Type'];

                        // If feed is known and enabled, validate data and save report
                        if ($this->isKnownFeed() && $this->isEnabledFeed()) {
                            // Sanity check
                            if ($this->hasRequiredFields($report) === true) {
                                // Event has all requirements met, filter and add!
                                $report = $this->applyFilters($report);

                                $this->events[] = [
                                    'source'        => config("{$this->configBase}.parser.name"),
                                    'ip'            => $report['Source'],
                                    'domain'        => false,
                                    'uri'           => false,
                                    'class'         => config("{$this->configBase}.feeds.{$this->feedName}.class"),
                                    'type'          => config("{$this->configBase}.feeds.{$this->feedName}.type"),
                                    'timestamp'     => strtotime(str_replace('\'', '', $report['Date'])),
                                    'information'   => json_encode($report),
                                ];
                            }
                        }
                    } else {
                        $this->warningCount++;
                    }
                }
            }
        }

        if ($foundArf === false) {
            // Didn't find an ARF report, go scrape the email body!
            $body = $this->parsedMail->getMessageBody();
            $this->feedName = 'botnet-infection';

            // If feed is known and enabled, validate data and save report
            if ($this->isKnownFeed() && $this->isEnabledFeed()) {
                preg_match_all('/  - ([^:]+): ([^\n]+)\n/', $body, $matches);
                $report = array_combine($matches[1], array_map('trim', $matches[2]));

                // Get IP address
                preg_match(
                    '/(?:Offending|Source) IP:[ ]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\n/',
                    $body,
                    $matches
                );
                if (count($matches) == 2 && empty($report['ip'])) {
                    $report['ip'] = $matches[1];
                }

                // Sanity check
                if ($this->hasRequiredFields($report) === true) {
                    // Event has all requirements met, filter and add!
                    $report = $this->applyFilters($report);

                    $this->events[] = [
                        'source'        => config("{$this->configBase}.parser.name"),
                        'ip'            => $report['ip'],
                        'domain'        => false,
                        'uri'           => false,
                        'class'         => config("{$this->configBase}.feeds.{$this->feedName}.class"),
                        'type'          => config("{$this->configBase}.feeds.{$this->feedName}.type"),
                        'timestamp'     => strtotime($report['Time']),
                        'information'   => json_encode($report),
                    ];
                }
            }
        }

        return $this->success();
    }
}
