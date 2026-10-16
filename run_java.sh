#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_PROJECT="$SCRIPT_DIR/Packet_analyzer"

JAVA_CMD="java"
if [ -f "/c/Program Files/JetBrains/IntelliJ IDEA 2025.2.5/jbr/bin/java.exe" ]; then
    JAVA_CMD="/c/Program Files/JetBrains/IntelliJ IDEA 2025.2.5/jbr/bin/java.exe"
fi

cd "$ROOT_PROJECT" || exit 1
"$JAVA_CMD" -cp "java/bin" com.dpianalyzer.Main "$@"
