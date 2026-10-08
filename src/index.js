require('dotenv').config();
const { Client, GatewayIntentBits, Events, ActivityType } = require('discord.js');
const fs = require('fs');
const path = require('path');
const { handlePrefixMessage, ALLOWED_CHANNEL_IDS } = require('./lib/prefix');
const changelog = require('./lib/changelog');

// ---- Required .env ------------------------------------------------------
// The bot refuses to boot without real configuration (no silent
// token-less/degraded runs that confuse operators).
const ENV_PATH = path.join(__dirname, '..', '.env');
if (!fs.existsSync(ENV_PATH) && !process.env.DISCORD_TOKEN) {
  console.error('[Fatal] Missing .env file. Copy .env.example to .env and fill in DISCORD_TOKEN.');
  process.exit(1);
}
if (!process.env.DISCORD_TOKEN) {
  console.error('[Fatal] DISCORD_TOKEN is not set. Put it in .env.');
  process.exit(1);
}
// Note: `.deobfuscate` / `.detect` / `.luraph` use the external LeakD API
// (X-Api-Key). Everything else (.l/.l2/.get/.luarmor/.jnkie) runs on the
// local Luau pipeline.
if (!process.env.LEAKD_API_KEY && !process.env.UPLOAD_API_TOKEN) {
  console.warn('[Warning] LEAKD_API_KEY is not set — only `.deobfuscate`/`.detect`/`.luraph` need it; all other commands work without it.');
}

const client = new Client({
  // MessageContent is privileged: enable it in the Developer Portal for
  // prefix commands (.l / .l2 / .deobfuscate) to be seen.
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent]
});

client.once(Events.ClientReady, (c) => {
  console.log(`[Nita Bot] Online as ${c.user.tag} (locked to ${ALLOWED_CHANNEL_IDS.length} channel(s): ${ALLOWED_CHANNEL_IDS.join(', ')})`);
  try {
    c.user.setPresence({
      activities: [{ name: '.help · unpack & trace Luau', type: ActivityType.Listening }],
      status: 'online',
    });
  } catch { /* best-effort */ }
  // Daily changelog to a webhook. Opt-in: without CHANGELOG_WEBHOOK_URL this
  // logs a single "disabled" line and never fires. Started after ready so a
  // failed post can never block login.
  try {
    changelog.startDailyTimer();
  } catch (err) {
    console.warn('[Changelog] timer failed to start:', err.message);
  }
});

// Handle unhandled rejections to prevent crashes
process.on('unhandledRejection', (error) => {
  console.error('[Unhandled Rejection]', error);
});

process.on('uncaughtException', (error) => {
  console.error('[Uncaught Exception]', error);
});

// Prefix commands (.l / .l2 / .deobfuscate) — channel lock enforced inside.
client.on(Events.MessageCreate, async (message) => {
  try {
    await handlePrefixMessage(message);
  } catch (err) {
    console.error('[Error] Prefix command failed:', err.message);
  }
});

// Handle disconnects and reconnections
client.on(Events.ShardDisconnect, (event, shardId) => {
  console.warn(`[Shard ${shardId}] Disconnected. Code: ${event.code}`);
});

client.on(Events.ShardReconnecting, (shardId) => {
  console.log(`[Shard ${shardId}] Reconnecting...`);
});

client.on(Events.ShardResume, (shardId, replayedEvents) => {
  console.log(`[Shard ${shardId}] Resumed. Replayed ${replayedEvents} events.`);
});

client.login(process.env.DISCORD_TOKEN).catch(err => {
  console.error('[Fatal] Failed to login:', err);
  process.exit(1);
});
