// Shared rich-embed presentation for every bot reply.
//
// Every outbound embed passes through scrubSecrets() (like plain-text
// replies did) and is clamped to Discord's limits:
//   title ≤ 256, description ≤ 4096, field name ≤ 256, field value ≤ 1024,
//   ≤ 25 fields, total ≤ 6000 chars.
// replyEmbed/editEmbed fall back to plain text if the channel rejects
// embeds, so the bot never goes silent.
const { EmbedBuilder } = require('discord.js');
const { scrubSecrets } = require('./safety');

const COLORS = {
  success: 0x57F287, // green
  error: 0xED4245, // red
  warn: 0xFEE75C, // yellow
  info: 0x5865F2, // blurple
};

const FOOTER = 'Nita Bot · local Luau pipeline';

function clampText(s, max) {
  const clean = scrubSecrets(s == null ? '' : String(s));
  if (clean.length <= max) return clean;
  return clean.slice(0, max) + '\n…(truncated)';
}

// Fenced code preview that always fits a field/description budget.
function codePreview(lang, text, max = 1200) {
  const body = scrubSecrets(text == null ? '' : String(text));
  const shown = body.length > max ? body.substring(0, max) + '\n…(truncated, see file)' : body;
  return '```' + (lang || 'lua') + '\n' + shown + '\n```';
}

function makeEmbed({ title, description, color, fields }) {
  const e = new EmbedBuilder().setColor(color || COLORS.info).setTimestamp(new Date());
  if (title) e.setTitle(scrubSecrets(String(title)).slice(0, 256));
  if (description) e.setDescription(clampText(description, 3900));
  if (Array.isArray(fields)) {
    e.addFields(fields.slice(0, 25).map((f) => ({
      name: scrubSecrets(String(f.name || '—')).slice(0, 256) || '—',
      value: clampText(f.value || '—', 1000) || '—',
      inline: !!f.inline,
    })));
  }
  e.setFooter({ text: FOOTER });
  return e;
}

// Plain-text rendering of an embed payload (fallback path).
function flattenPayload(payload) {
  if (!payload) return '…';
  if (typeof payload === 'string') return clampText(payload, 1900);
  const parts = [];
  if (payload.content) parts.push(payload.content);
  for (const em of payload.embeds || []) {
    const d = em && em.data ? em.data : em;
    if (d.title) parts.push('**' + d.title + '**');
    if (d.description) parts.push(d.description);
    for (const f of d.fields || []) parts.push(`**${f.name}**\n${f.value}`);
    if (d.footer && d.footer.text) parts.push('_' + d.footer.text + '_');
  }
  return clampText(parts.join('\n\n') || '…', 1900);
}

async function replyEmbed(message, payload) {
  try {
    return await message.reply(payload);
  } catch {
    return await message.reply(flattenPayload(payload));
  }
}

async function editEmbed(statusMsg, payload) {
  try {
    return await statusMsg.edit(payload);
  } catch {
    return await statusMsg.edit(flattenPayload(payload));
  }
}

// Deliver an embed edit PLUS result files so the files can never be lost
// silently: if the combined edit throws (Discord size limits, >10 files,
// network blip), the text part still lands via editEmbed and the files go
// out as a follow-up channel message. Anything that still fails is logged
// and reported in plain text instead of vanishing.
async function editEmbedWithFiles(statusMsg, message, payload, files) {
  const list = Array.isArray(files) ? files.filter(Boolean) : [];
  if (list.length === 0) {
    return editEmbed(statusMsg, payload);
  }
  try {
    return await statusMsg.edit({ ...payload, files: list });
  } catch (err) {
    console.error('[embed] edit-with-files failed, splitting text/files:', err && err.message ? err.message : err);
  }
  await editEmbed(statusMsg, payload).catch((err) => {
    console.error('[embed] text edit also failed:', err && err.message ? err.message : err);
  });
  try {
    await message.channel.send({ files: list });
  } catch (err2) {
    console.error('[embed] follow-up file send failed:', err2 && err2.message ? err2.message : err2);
    try {
      await message.reply(
        `Result files could not be attached (${scrubSecrets(err2.message).substring(0, 160)}). They remain in the session temp dir on the host.`
      );
    } catch { /* last resort failed; logged above */ }
  }
  return null;
}

module.exports = { COLORS, FOOTER, clampText, codePreview, makeEmbed, replyEmbed, editEmbed, editEmbedWithFiles, flattenPayload };
