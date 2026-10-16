package com.dpianalyzer.model;

public enum PacketAction {
    FORWARD,    // Forward packet to output
    DROP,       // Block / drop packet
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log
}
