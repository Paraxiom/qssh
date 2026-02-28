#!/bin/bash
# QSSH Security Test Suite - Simple Version (no external dependencies)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PORT=${QSSH_TEST_PORT:-22222}
QSSHD_PID=""

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}       QSSH Security Test Suite - Simple Version        ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

# Function to start test daemon
start_qsshd() {
    echo -e "\n${YELLOW}Starting QSSH daemon...${NC}"

    # Generate test host key if needed
    if [ ! -f ~/.qssh/test_host_key ]; then
        mkdir -p ~/.qssh
        ./target/debug/qssh-keygen -t falcon512 -f ~/.qssh/test_host_key --host-key -y
    fi

    # Start daemon
    ./target/debug/qsshd -l "127.0.0.1:$PORT" --host-key ~/.qssh/test_host_key \
        -v 2>/tmp/qsshd_test.log &
    QSSHD_PID=$!

    sleep 2

    if kill -0 $QSSHD_PID 2>/dev/null; then
        echo -e "${GREEN}✓ Daemon started (PID: $QSSHD_PID)${NC}"
    else
        echo -e "${RED}✗ Failed to start daemon${NC}"
        exit 1
    fi
}

# Cleanup
stop_qsshd() {
    if [ ! -z "$QSSHD_PID" ]; then
        echo -e "\n${YELLOW}Stopping daemon...${NC}"
        kill $QSSHD_PID 2>/dev/null || true
    fi
}

trap stop_qsshd EXIT

# Build if needed
if [ ! -f ./target/debug/qssh ] || [ ! -f ./target/debug/qsshd ]; then
    echo -e "${YELLOW}Building QSSH...${NC}"
    cargo build --bins
fi

start_qsshd

echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                 1. FUZZING TESTS                       ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

echo -e "\n${YELLOW}Testing malformed SSH banners...${NC}"
python3 - << 'EOF'
import socket
import time

banners = [
    b"SSH-2.0-Normal\r\n",          # Valid
    b"SSH-1.0-Old\r\n",             # Old version
    b"NOT_SSH\r\n",                 # Not SSH
    b"SSH-2.0-" + b"A" * 1000,      # No line ending
    b"\x00" * 100,                  # Binary garbage
    b"",                            # Empty
]

for i, banner in enumerate(banners, 1):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect(("127.0.0.1", 22222))
        s.send(banner)
        resp = s.recv(256)
        result = "Responded" if resp else "No response"
        print(f"  Test {i}: {result}")
        s.close()
    except socket.timeout:
        print(f"  Test {i}: Timeout (good)")
    except ConnectionResetError:
        print(f"  Test {i}: Connection reset (good)")
    except Exception as e:
        print(f"  Test {i}: {type(e).__name__}")
    time.sleep(0.1)
EOF

echo -e "\n${YELLOW}Testing oversized packets...${NC}"
for size in 1000 10000 65535 1000000; do
    echo -n "  Size $size: "
    head -c $size /dev/urandom | nc -w 1 127.0.0.1 $PORT 2>/dev/null
    if kill -0 $QSSHD_PID 2>/dev/null; then
        echo -e "${GREEN}Survived${NC}"
    else
        echo -e "${RED}Crashed!${NC}"
        start_qsshd
    fi
done

echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}            2. QUANTUM DOWNGRADE TESTS                  ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

echo -e "\n${YELLOW}Testing algorithm downgrade attempts...${NC}"
for algo in none rsa classical weak disabled; do
    echo -n "  Trying --pq-algo=$algo: "
    timeout 1 ./target/debug/qssh --pq-algo "$algo" test@127.0.0.1:$PORT 2>&1 | \
        grep -q "Invalid\|Error\|not supported" && echo -e "${GREEN}Rejected${NC}" || echo -e "${RED}Accepted!${NC}"
done

echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}              3. CONNECTION FLOOD TEST                  ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

echo -e "\n${YELLOW}Opening multiple connections...${NC}"
CONN_COUNT=0
MAX_CONNS=100

for i in $(seq 1 $MAX_CONNS); do
    if nc -z 127.0.0.1 $PORT 2>/dev/null; then
        ( nc 127.0.0.1 $PORT </dev/null >/dev/null 2>&1 & )
        CONN_COUNT=$((CONN_COUNT + 1))

        if [ $((i % 20)) -eq 0 ]; then
            echo -n "  $i connections... "
            if kill -0 $QSSHD_PID 2>/dev/null; then
                echo -e "${GREEN}OK${NC}"
            else
                echo -e "${RED}Daemon died!${NC}"
                break
            fi
        fi
    else
        echo -e "  ${YELLOW}Connection refused after $CONN_COUNT connections${NC}"
        break
    fi
done

echo -e "  Max connections: $CONN_COUNT"

echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}             4. TIMING ATTACK DETECTION                 ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

echo -e "\n${YELLOW}Measuring authentication timing...${NC}"
for user in root admin test nonexistent; do
    echo -n "  User '$user': "

    START=$(date +%s%N)
    timeout 0.5 ./target/debug/qssh "$user@127.0.0.1:$PORT" \
        -o BatchMode=yes 2>/dev/null || true
    END=$(date +%s%N)

    ELAPSED=$((($END - $START) / 1000000))  # Convert to ms
    echo "${ELAPSED}ms"
done

echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                  5. MEMORY TEST                        ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

echo -e "\n${YELLOW}Sending large payloads...${NC}"
for mb in 1 10 50; do
    size=$((mb * 1024 * 1024))
    echo -n "  Sending ${mb}MB: "

    dd if=/dev/zero bs=$size count=1 2>/dev/null | \
        timeout 2 nc 127.0.0.1 $PORT >/dev/null 2>&1

    if kill -0 $QSSHD_PID 2>/dev/null; then
        # Check memory usage
        MEM=$(ps -o rss= -p $QSSHD_PID | awk '{print int($1/1024)}')
        echo -e "${GREEN}Survived${NC} (using ${MEM}MB RAM)"
    else
        echo -e "${RED}Crashed!${NC}"
        start_qsshd
    fi
done

echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                   TEST RESULTS                         ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

if [ -f /tmp/qsshd_test.log ]; then
    ERRORS=$(grep -c "ERROR\|PANIC" /tmp/qsshd_test.log 2>/dev/null || echo 0)
    WARNINGS=$(grep -c "WARN" /tmp/qsshd_test.log 2>/dev/null || echo 0)

    echo -e "\n${YELLOW}Log Analysis:${NC}"
    echo "  Errors: $ERRORS"
    echo "  Warnings: $WARNINGS"

    if [ $ERRORS -gt 0 ]; then
        echo -e "\n${RED}Sample errors:${NC}"
        grep "ERROR\|PANIC" /tmp/qsshd_test.log | head -3
    fi
fi

if kill -0 $QSSHD_PID 2>/dev/null; then
    echo -e "\n${GREEN}✓ Daemon survived all tests${NC}"
else
    echo -e "\n${RED}✗ Daemon crashed during tests${NC}"
fi

echo -e "\n${GREEN}Test suite completed!${NC}"
echo "Logs: /tmp/qsshd_test.log"