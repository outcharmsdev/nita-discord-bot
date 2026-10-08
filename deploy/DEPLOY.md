# Deploy runbook — Nita bot on an isolated host

Goal: move the bot off the shared container onto a VPS you control, behind a
default-deny egress firewall. The bot keeps full features (arbitrary loader
URLs still fetch — they're public HTTPS); cloud metadata, LAN boxes, and all
other non-web egress become unreachable at L3. The in-code SSRF guard +
IP-logger blocklist stay on as the inner layer.

## 0. Prereqs (your provider account)

- One VPS, Ubuntu 24.04 LTS (1 vCPU / 1 GB is plenty).
- Your Discord user ID (for `OWNER_IDS`) and the channel/token values that
  currently live in this repo's `.env` (you will retype them — never copy
  the file over chat or commit it).

## 1. Provider firewall FIRST (before installing anything)

Create a firewall / security group, attach it to the VPS:

| Direction | Proto | Port(s)                 | Destination              | Purpose                              |
|-----------|-------|-------------------------|--------------------------|--------------------------------------|
| Out       | TCP   | 443                     | `0.0.0.0/0`, `::/0`      | Discord, Pastefy, LeakD, loader URLs |
| Out       | TCP   | 80                      | `0.0.0.0/0`, `::/0`      | http redirect chains                 |
| Out       | UDP   | 53                      | `0.0.0.0/0`, `::/0`      | DNS                                  |
| Out       | all   | —                       | `169.254.169.254/32`     | **DENY cloud metadata (explicit)**   |
| Out       | all   | —                       | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | **DENY private nets (explicit)** |
| Out       | all   | all                     | all                      | **DENY (default rule, lowest priority)** |
| In        | TCP   | 22                      | **your IP only**         | SSH                                  |
| In        | all   | all                     | all                      | **DENY (default)**                   |

Hetzner CLI equivalent (adjust names/zone to yours):

```bash
hcloud firewall create --name nita-bot
hcloud firewall add-rule nita-bot --direction out --protocol tcp --port 443 --source-ips 0.0.0.0/0 --source-ips ::/0
hcloud firewall add-rule nita-bot --direction out --protocol tcp --port 80 --source-ips 0.0.0.0/0 --source-ips ::/0
hcloud firewall add-rule nita-bot --direction out --protocol udp --port 53 --source-ips 0.0.0.0/0 --source-ips ::/0
# then in the panel: egress DENY all (lowest priority), explicit DENY for
# 169.254.169.254/32 + RFC1918, ingress DENY all except SSH from your IP.
```

The bot needs **zero inbound ports** (it dials out to Discord over websocket).

## 2. Base hardening (SSH into the VPS)

```bash
# user + SSH (as root, once)
adduser --disabled-password --gecos '' nita
mkdir -p /home/nita/.ssh && chmod 700 /home/nita/.ssh
# paste YOUR public key:
echo 'ssh-ed25519 AAAA... you@machine' > /home/nita/.ssh/authorized_keys
chmod 600 /home/nita/.ssh/authorized_keys && chown -R nita:nita /home/nita/.ssh
usermod -aG sudo nita
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl reload sshd
apt-get update && apt-get install -y unattended-upgrades curl ca-certificates
```

## 3. Runtime (as `nita`)

```bash
# Node 20 LTS (matched to v20.19.2 running today)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version  # expect v20.x

# Lune 0.10.5 (match tracer behavior 1:1)
mkdir -p ~/.local/bin
curl -fsSL -o /tmp/lune.zip \
  https://github.com/lune-org/lune/releases/download/v0.10.5/lune-0.10.5-linux-x86_64.zip
unzip -o /tmp/lune.zip -d ~/.local/bin && chmod +x ~/.local/bin/lune
lune --version  # expect 0.10.5
```

## 4. Deploy the code (as `nita`)

```bash
sudo mkdir -p /opt/nita-discord-bot
sudo chown nita:nita /opt/nita-discord-bot
cd /opt/nita-discord-bot
# copy the tree WITHOUT secrets/scratch: exclude .env, node_modules/,
# temp/, nohup.out, deploy/ (this folder is docs-only)
# e.g.: rsync -av --exclude=.env --exclude=node_modules --exclude=temp \
#         --exclude=nohup.out ./ user@oldhost:/app/test/discord-bot/ ./
npm ci
```

Then create `/opt/nita-discord-bot/.env` by hand (`chmod 600 .env`):

```env
DISCORD_TOKEN=<paste>
CLIENT_ID=<paste>
ALLOWED_CHANNEL_ID=<paste>
LUNE_BIN=/home/nita/.local/bin/lune
LEAKD_API_KEY=<paste>
LEAKD_API_BASE_URL=https://leakd.up.railway.app
OWNER_IDS=<your discord user id>
PROTECTION_ENABLED=1
# optional: PROTECTION_LOG_CHANNEL_ID=<channel id for nuke/raid alerts>
# optional: PASTEFY_URL=https://pastefy.app
```

Variable reference is `.env.example` in this repo — keep this file in sync
with any new `REQUIRED` entries there.

## 5. Install + start the service (as root)

```bash
cp /opt/nita-discord-bot/deploy/nita-bot.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nita-bot
sleep 12
journalctl -u nita-bot --no-pager -n 15   # expect: Online as …"
```

Useful afterwards:

```bash
journalctl -u nita-bot -f        # live logs (replaces tailing nohup.out)
systemctl restart nita-bot       # after any code/.env change
```

## 6. Acceptance checklist (do all of these before step 7)

- [ ] `node --test` green inside `/opt/nita-discord-bot` (expect 18/18).
- [ ] Bot replies to `.help` in the locked channel.
- [ ] `.get https://raw.githubusercontent.com/AnonymoDGH/scripts/refs/heads/main/scagent.lua` succeeds end-to-end (proves egress + features intact).
- [ ] From the VPS shell (as nita): `curl -m5 http://169.254.169.254/` **fails/blocked** while `curl -sI https://discord.com` works.
- [ ] `ls -l /opt/nita-discord-bot/.env` shows `-rw------- nita nita`.

## 7. Decommission the old instance

Only after step 6 is fully green — two live sessions fight over one token
(Discord disconnects the older one, but clean is clean):

```bash
# on the OLD host:
pkill -f 'node src/index.js'   # then confirm: pgrep -f 'node src/index' | empty
```

## Troubleshooting

| Symptom | Likely cause → fix |
|---|---|
| `Online` never appears | wrong `DISCORD_TOKEN` / egress 443 blocked → check journal + firewall |
| `.l` says Lune failed | `LUNE_BIN` path wrong → `sudo -u nita /home/nita/.local/bin/lune --version` |
| `Permission denied` writing temp/ | `ReadWritePaths` mismatch → `ls -ld /opt/nita-discord-bot/temp` must be `nita:nita` |
| systemd sandbox too strict | comment out `ProtectSystem`/`PrivateTmp` lines, `daemon-reload`, restart — then tell the maintainer which line broke |
| Two bots replying at once | old instance still alive → step 7 |
