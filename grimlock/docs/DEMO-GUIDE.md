# Grimlock Demo & Testing Guide

> Manual testing guide for demonstrating transparent A2A security with eBPF + kTLS

## Prerequisites

- SSH access to both hosts
- Grimlock built on both hosts
- A2A agents running in Docker containers

## Test Infrastructure

| Host | IP | Role |
|------|-----|------|
| Host 1 | <HOST_A_IP> | planning-agent |
| Host 2 | <HOST_B_IP> | research-agent |

SSH command:
```bash
ssh -i ~/.ssh/<your-key>.pem ubuntu@<IP>
```

---

## Quick Start (Copy-Paste Commands)

### Terminal 1: Start Host 2 (Receiver)

```bash
ssh -i ~/.ssh/<your-key>.pem ubuntu@<HOST_B_IP>

# Kill any existing Grimlock
sudo killall -9 grimlock 2>/dev/null

# Start A2A agent if not running
docker ps | grep research-agent || docker start research-agent

# Start Grimlock
cd ~/grimlock/cmd/grimlock
sudo ./grimlock --cgroup=/sys/fs/cgroup --peers=<HOST_A_IP> \
    --cert=/home/ubuntu/grimlock/certs/agent-b.crt \
    --key=/home/ubuntu/grimlock/certs/agent-b.pem \
    --ca=/home/ubuntu/grimlock/certs/ca.crt
```

### Terminal 2: Start Host 1 (Sender)

```bash
ssh -i ~/.ssh/<your-key>.pem ubuntu@<HOST_A_IP>

# Kill any existing Grimlock
sudo killall -9 grimlock 2>/dev/null

# Start A2A agent if not running
docker ps | grep planning-agent || docker start planning-agent

# Start Grimlock
cd ~/grimlock/cmd/grimlock
sudo ./grimlock --cgroup=/sys/fs/cgroup --peers=<HOST_B_IP> \
    --cert=/home/ubuntu/grimlock/certs/agent-a.crt \
    --key=/home/ubuntu/grimlock/certs/agent-a.pem \
    --ca=/home/ubuntu/grimlock/certs/ca.crt
```

---

## Demo Scenarios

### Demo 1: Basic A2A Discovery (Agent Card)

**What it shows:** Agent A discovers Agent B's capabilities through encrypted tunnel

```bash
# On Host 1
curl -s http://<HOST_B_IP>:8080/.well-known/agent.json | jq .
```

**Expected output:**
```json
{
  "name": "research-agent",
  "description": "Grimlock demo agent...",
  "url": "http://<HOST_B_IP>:8080/a2a",
  "version": "1.0.0",
  "capabilities": {...},
  "skills": [...]
}
```

**What to observe in Grimlock logs:**
```
[EVENT] CONNECT ... to <HOST_B_IP>:8080
[LOCAL] Redirected connection from 127.0.0.1:xxxxx
[LOCAL] Created dedicated tunnel to <HOST_B_IP>
[LOCAL] Sent 104 bytes through tunnel
```

### Demo 2: A2A JSON-RPC Message

**What it shows:** Full A2A protocol message exchange through encrypted tunnel

```bash
# On Host 1
curl -s -X POST http://<HOST_B_IP>:8080/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{"text": "Hello from Agent A!"}]
      }
    }
  }' | jq .
```

**Expected output:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "id": "task-...",
    "status": {"state": "completed"},
    "artifacts": [...]
  },
  "id": 1
}
```

### Demo 3: Bidirectional Communication

**What it shows:** Both directions work (A→B and B→A)

```bash
# On Host 2 (reverse direction)
curl -s http://<HOST_A_IP>:8080/.well-known/agent.json | jq .name
# Should return: "planning-agent"
```

### Demo 4: Verify Encryption with tcpdump

**What it shows:** Traffic on wire is encrypted (TLS 1.3)

```bash
# Terminal on Host 2: Start packet capture
sudo tcpdump -i any port 9443 -X -c 20 &

# Terminal on Host 1: Send request
curl -s http://<HOST_B_IP>:8080/.well-known/agent.json > /dev/null

# Observe tcpdump output - should show encrypted bytes, NOT readable HTTP
```

**What to look for:**
- NO readable text like "GET", "HTTP", "agent.json"
- Random-looking bytes (encrypted TLS payload)
- TLS record headers: `17 03 03` (TLS 1.3 application data)

### Demo 5: Connection Interception Proof

**What it shows:** curl thinks it connected to remote IP, but actually connected to localhost

```bash
# On Host 1
curl -v http://<HOST_B_IP>:8080/.well-known/agent.json 2>&1 | grep "Connected to"
```

**Expected output:**
```
* Connected to <HOST_B_IP> (127.0.0.1) port 8080 (#0)
```

The `(127.0.0.1)` proves eBPF redirected the connection!

---

## Verification Commands

### Check Grimlock is Running

```bash
# On either host
ps aux | grep grimlock
sudo netstat -tlnp | grep -E "9443|15001"
```

Expected ports:
- `9443` - Tunnel listener (for peer Grimlock connections)
- `15001` - Local listener (for redirected agent connections)

### Check A2A Agents are Running

```bash
# On either host
docker ps | grep agent
curl -s localhost:8080/.well-known/agent.json | jq .name
```

### Check eBPF Programs are Loaded

```bash
# On either host (as root)
sudo bpftool prog list | grep grimlock
```

Expected:
```
xxx: sock_ops  name grimlock_sockops ...
xxx: cgroup_sock_addr  name grimlock_connect4 ...
```

### Check kTLS is Enabled

```bash
# Check kernel module
lsmod | grep tls
# Should show: tls

# Check Grimlock logs for kTLS confirmation
grep "kTLS enabled" /tmp/grimlock.log
```

---

## Troubleshooting

### Issue: curl times out

**Check:**
1. Is Grimlock running on both hosts?
2. Is the A2A agent container running?
3. Is port 9443 open between hosts?

```bash
# Test direct connectivity
nc -zv <HOST_B_IP> 9443
```

### Issue: "Connection refused"

**Check:**
1. Grimlock might have crashed - check logs
2. Agent container might have stopped

```bash
# Check Grimlock logs
tail -50 /tmp/grimlock.log

# Restart agent container
docker start research-agent  # or planning-agent
```

### Issue: SSH locked out

**NEVER** attach eBPF to root cgroup without SSH protection!

Current code protects SSH:
```c
// CRITICAL: Never redirect SSH traffic
if (dst_port == SSH_PORT)
    return 1;  // Allow without redirect
```

If locked out, reboot the instance from AWS console.

---

## Performance Testing

### Latency Test

```bash
# Baseline (direct, no Grimlock)
# First stop Grimlock, then:
time curl -s http://<HOST_B_IP>:8080/.well-known/agent.json > /dev/null

# With Grimlock (restart Grimlock, then:)
time curl -s http://<HOST_B_IP>:8080/.well-known/agent.json > /dev/null
```

### Multiple Requests

```bash
# Send 10 requests
for i in {1..10}; do
  curl -s http://<HOST_B_IP>:8080/.well-known/agent.json > /dev/null
  echo "Request $i complete"
done
```

---

## Clean Up

### Stop Grimlock

```bash
sudo killall grimlock
```

### Stop A2A Agents

```bash
docker stop planning-agent  # Host 1
docker stop research-agent  # Host 2
```

### Remove eBPF Programs (automatic on Grimlock exit)

eBPF programs are automatically detached when Grimlock exits.
To verify they're gone:

```bash
sudo bpftool prog list | grep grimlock
# Should return nothing
```

---

## Demo Script (One-Liner)

For a quick demo, run this from your local machine:

```bash
# Start both Grimlocks in background, wait, then test
ssh -i ~/.ssh/<your-key>.pem ubuntu@<HOST_B_IP> 'sudo killall grimlock 2>/dev/null; cd ~/grimlock/cmd/grimlock && sudo ./grimlock --cgroup=/sys/fs/cgroup --peers=<HOST_A_IP> --cert=/home/ubuntu/grimlock/certs/agent-b.crt --key=/home/ubuntu/grimlock/certs/agent-b.pem --ca=/home/ubuntu/grimlock/certs/ca.crt > /tmp/grimlock.log 2>&1 &' && \
ssh -i ~/.ssh/<your-key>.pem ubuntu@<HOST_A_IP> 'sudo killall grimlock 2>/dev/null; cd ~/grimlock/cmd/grimlock && sudo ./grimlock --cgroup=/sys/fs/cgroup --peers=<HOST_B_IP> --cert=/home/ubuntu/grimlock/certs/agent-a.crt --key=/home/ubuntu/grimlock/certs/agent-a.pem --ca=/home/ubuntu/grimlock/certs/ca.crt > /tmp/grimlock.log 2>&1 &' && \
sleep 5 && \
echo "=== Testing A2A through Grimlock ===" && \
ssh -i ~/.ssh/<your-key>.pem ubuntu@<HOST_A_IP> 'curl -s http://<HOST_B_IP>:8080/.well-known/agent.json | head -c 100' && \
echo "..." && \
echo "=== SUCCESS! ===" 
```
