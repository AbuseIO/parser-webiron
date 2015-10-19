<?php

return [
    'parser' => [
        'name'          => 'Webiron',
        'enabled'       => true,
        'report_file'   => '/arf_report[0-9]+/i',
        'sender_map'    => [
            '/@abuse-reporting.webiron.com/',
        ],
        'body_map'      => [
            //
        ],
    ],

    'feeds' => [
        'web-attack' => [
            'class'     => 'DDoS sending Server',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'Source',
            ],
        ],
        'botnet-infection' => [
            'class'     => 'Botnet infection',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
            ],
        ],
    ],
];
