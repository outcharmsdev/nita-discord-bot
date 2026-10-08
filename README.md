# Nita

Bot Discord para processamento local de scripts Luau, com comandos por prefixo e proteção de canal.

## Configuração

1. Copie `.env.example` para `.env`.
2. Preencha `DISCORD_TOKEN` e os demais valores necessários.
3. Instale as dependências com `npm install`.
4. Inicie com `npm start`.

Nunca publique `.env`, tokens, webhooks, bancos de dados ou arquivos temporários. O repositório foi limpo antes da publicação.

## Comandos

Os comandos disponíveis estão documentados no próprio painel de ajuda do bot. O acesso é limitado pelos canais definidos em `ALLOWED_CHANNEL_IDS`.

## Deploy

Veja [`deploy/DEPLOY.md`](deploy/DEPLOY.md) para instruções de execução como serviço.
