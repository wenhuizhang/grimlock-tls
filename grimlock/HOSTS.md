# Grimlock Test Infrastructure

## Test Hosts

| Host | IP Address | Role |
|------|------------|------|
| Host 1 | <HOST_A_IP> | Agent A |
| Host 2 | <HOST_B_IP> | Agent B |

## SSH Access

```bash
# Host 1
# ssh -i "~/.ssh/<your-key>.pem" ubuntu@<HOST_A_IP>
ssh <host-a>


# Host 2
# ssh -i "~/.ssh/<your-key>.pem" ubuntu@<HOST_B_IP>
ssh <host-b>
```

## Quick Commands

```bash
# Check host status
ssh -i ~/.ssh/<your-key>.pem ubuntu@<HOST_A_IP> 'uname -r && uptime'
ssh -i ~/.ssh/<your-key>.pem ubuntu@<HOST_B_IP> 'uname -r && uptime'

# Deploy to both hosts
./scripts/deploy-remote.sh ubuntu@<HOST_A_IP> ~/.ssh/<your-key>.pem
./scripts/deploy-remote.sh ubuntu@<HOST_B_IP> ~/.ssh/<your-key>.pem
```

## Network

- Ensure security groups allow traffic between hosts on:
  - TCP 9443 (control plane / handshake)
  - TCP 8080 (test application traffic)
  - Or open all TCP between these two IPs for testing
