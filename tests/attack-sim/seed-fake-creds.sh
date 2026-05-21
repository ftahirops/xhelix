#!/bin/bash
# tests/attack-sim/seed-fake-creds.sh
#
# AUTHORIZED SECURITY TEST. Seeds REAL-FORMAT canary credentials
# spanning ~40 cloud providers, AI APIs, payment processors,
# package registries, infrastructure tools, and SSH key types.
#
# Every value embeds CANARYXHELIX so anyone who sees them on the
# attacker side can identify them as honey/bait. The FORMATS are
# real (length, prefix, structure) so malware regex hits.
#
# Run cleanup-sim.sh to remove all of these.

set -u
MARKER="CANARYXHELIX"

log() { echo "[seed $(date +%H:%M:%S)] $*"; }
log "=== seeding fake real-format credentials ==="

# ════════════════════════════════════════════════════════════════
# CLOUD: AWS
# ════════════════════════════════════════════════════════════════
mkdir -p "$HOME/.aws"
cat > "$HOME/.aws/credentials" <<EOF
[default]
aws_access_key_id = AKIA${MARKER:0:12}AA
aws_secret_access_key = ${MARKER}c2VjcmV0a2V5aXNoLWZha2UtYmFpdC0xMjM=
region = us-east-1

[prod]
aws_access_key_id = AKIA${MARKER:0:12}PR
aws_secret_access_key = ${MARKER}cHJvZHVjdGlvbi1mYWtlLXNlY3JldGtleQ=
region = us-west-2

[admin]
# Session credentials (STS) — temporary tokens
aws_access_key_id = ASIA${MARKER:0:12}AD
aws_secret_access_key = ${MARKER}YWRtaW4tc3RzLXNlc3Npb24tdGVtcG9yYXJ5=
aws_session_token = ${MARKER}.eyJhbGciOiJIUzI1NiJ9.SgVeryLongSessionTokenForSTSAssumeRoleResponseFakeBait1234567890ABCDEFGabcdefg.fakeSig
region = eu-west-1
EOF
cat > "$HOME/.aws/config" <<EOF
[default]
region = us-east-1
output = json
[profile prod]
region = us-west-2
[profile admin]
role_arn = arn:aws:iam::123456789012:role/AdminCanary${MARKER}
source_profile = default
EOF
log "AWS: ~/.aws/credentials (+session) + ~/.aws/config"

# ════════════════════════════════════════════════════════════════
# CLOUD: GCP / Google
# ════════════════════════════════════════════════════════════════
mkdir -p "$HOME/.config/gcloud"
cat > "$HOME/.config/gcloud/application_default_credentials.json" <<EOF
{
  "client_id": "${MARKER:0:8}012345678901-${MARKER:0:8}abcdefghijklmnopqrstuvwx.apps.googleusercontent.com",
  "client_secret": "${MARKER}-GOCSPX-fakeGoogleClientSecret123",
  "refresh_token": "1//0e${MARKER}fakeGoogleOAuthRefreshTokenForCanaryBaitVeryLongToken1234567890",
  "type": "authorized_user"
}
EOF
cat > "$HOME/gcp-service-account.json" <<EOF
{
  "type": "service_account",
  "project_id": "canary-${MARKER,,}-project",
  "private_key_id": "${MARKER}1234567890abcdef1234567890abcdef12345678",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ${MARKER}fakeGCPSvcAcctKey\n-----END PRIVATE KEY-----\n",
  "client_email": "canary-bait@canary-${MARKER,,}-project.iam.gserviceaccount.com",
  "client_id": "${MARKER}12345678901234567",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}
EOF
log "GCP: ~/.config/gcloud/application_default_credentials.json + ~/gcp-service-account.json"

# ════════════════════════════════════════════════════════════════
# CLOUD: Azure
# ════════════════════════════════════════════════════════════════
mkdir -p "$HOME/.azure"
cat > "$HOME/.azure/azureProfile.json" <<EOF
{
  "installationId": "${MARKER}-fake-install-uuid",
  "subscriptions": [{
    "id": "${MARKER}-1234-5678-9abc-def012345678",
    "name": "Canary-Bait-Subscription",
    "state": "Enabled",
    "tenantId": "${MARKER}-tenant-id-fake-bait-9876",
    "isDefault": true,
    "user": {"name": "canary@${MARKER,,}.onmicrosoft.com"}
  }]
}
EOF
cat > "$HOME/.azure/accessTokens.json" <<EOF
[{
  "tokenType": "Bearer",
  "expiresIn": 3599,
  "expiresOn": "2099-12-31 23:59:59.000000",
  "resource": "https://management.core.windows.net/",
  "accessToken": "${MARKER}.eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.fakeAzureAccessTokenForCanaryBaitLongJWT.${MARKER}sig",
  "refreshToken": "${MARKER}-azure-refresh-token-fake-bait-1234567890",
  "userId": "canary@${MARKER,,}.onmicrosoft.com",
  "_clientId": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
  "_authority": "https://login.microsoftonline.com/${MARKER}-tenant"
}]
EOF
# Azure service principal env file (common in CI)
cat > "$HOME/.azure-sp.env" <<EOF
AZURE_CLIENT_ID=${MARKER}-1111-2222-3333-444455556666
AZURE_CLIENT_SECRET=${MARKER}~Azure_Service_Principal_Secret_Bait_1234~
AZURE_TENANT_ID=${MARKER}-tenant-id-fake-bait-9876
AZURE_SUBSCRIPTION_ID=${MARKER}-1234-5678-9abc-def012345678
EOF
log "Azure: ~/.azure/azureProfile.json + accessTokens.json + ~/.azure-sp.env"

# ════════════════════════════════════════════════════════════════
# CLOUD: DigitalOcean, Linode, Hetzner, Vultr
# ════════════════════════════════════════════════════════════════
mkdir -p "$HOME/.config/doctl"
cat > "$HOME/.config/doctl/config.yaml" <<EOF
access-token: dop_v1_${MARKER}fakeDigitalOceanPersonalAccessToken1234567890abcdef
context: default
EOF
echo "${MARKER}-linode-personal-access-token-fake-bait-1234567890ab" > "$HOME/.linode-cli-token"
echo "${MARKER}-hetzner-cloud-api-token-fake-bait-very-long-1234567890abcdefghijklmnopqr" > "$HOME/.hetzner-cloud-token"
echo "VULTR_API_KEY=${MARKER}VULTRFAKEAPIKEYBAIT123456789ABCDEFG" > "$HOME/.vultr-api-token"
log "Cloud providers: DO + Linode + Hetzner + Vultr API tokens"

# ════════════════════════════════════════════════════════════════
# CLOUD: Cloudflare
# ════════════════════════════════════════════════════════════════
cat > "$HOME/.cloudflare.cfg" <<EOF
[CloudFlare]
email = canary@${MARKER,,}.invalid
api_key = ${MARKER}cloudflareGlobalApiKeyFakeBait1234
api_token = ${MARKER}cloudflareAPIv4TokenFakeBait1234567890_abcDEFghi-jklMNOpqrSTU
EOF
log "Cloudflare: ~/.cloudflare.cfg"

# ════════════════════════════════════════════════════════════════
# CONTAINERS: Docker, Kubernetes
# ════════════════════════════════════════════════════════════════
mkdir -p "$HOME/.docker" "$HOME/.kube"
cat > "$HOME/.docker/config.json" <<EOF
{
  "auths": {
    "https://index.docker.io/v1/": {"auth": "${MARKER}ZG9ja2VyaHViLWZha2UtYXV0aDo="},
    "ghcr.io":    {"auth": "${MARKER}Z2hjci1mYWtlLWF1dGgtMTIzNA=="},
    "registry.gitlab.com": {"auth": "${MARKER}Z2l0bGFiLWZha2UtYXV0aA=="},
    "quay.io":    {"auth": "${MARKER}cXVheS1mYWtlLWF1dGgtMTIz"}
  },
  "credsStore": "desktop",
  "experimental": "enabled"
}
EOF
cat > "$HOME/.kube/config" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: prod-cluster
  cluster:
    server: https://k8s-prod.${MARKER,,}.invalid:6443
    certificate-authority-data: ${MARKER}LS0tLS1CRUdJTi1mYWtlLWNh
- name: staging-cluster
  cluster:
    server: https://k8s-staging.${MARKER,,}.invalid:6443
contexts:
- name: prod
  context: {cluster: prod-cluster, user: prod-admin, namespace: default}
- name: staging
  context: {cluster: staging-cluster, user: staging-readonly}
current-context: prod
users:
- name: prod-admin
  user:
    token: ${MARKER}.eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fakeBearerTokenForK8sProdAdminBaitVeryLongJWTPayload.${MARKER}sig
- name: staging-readonly
  user:
    client-certificate-data: ${MARKER}LS0tLS1CRUdJTi1jZXJ0
    client-key-data: ${MARKER}LS0tLS1CRUdJTi1rZXk=
EOF
log "Containers: ~/.docker/config.json + ~/.kube/config (multi-cluster)"

# ════════════════════════════════════════════════════════════════
# AI APIs: Anthropic, OpenAI, Cohere, HuggingFace, Mistral,
#         Replicate, Stability, Together, Groq
# ════════════════════════════════════════════════════════════════
cat > "$HOME/.anthropic" <<EOF
ANTHROPIC_API_KEY=sk-ant-api03-${MARKER}_AnthropicApiKeyFakeBaitForCanaryAttackTest1234567890abcdefghijklmnop_${MARKER}AA
EOF
cat > "$HOME/.openai" <<EOF
OPENAI_API_KEY=sk-${MARKER}OpenAIApiKeyFakeBaitForCanary1234567890abcdefghijklmnop
OPENAI_ORG_ID=org-${MARKER}OpenAIOrganizationIDFake12
EOF
cat > "$HOME/.ai-keys.env" <<EOF
# Multi-provider AI credential bundle (common malware target)
ANTHROPIC_API_KEY=sk-ant-api03-${MARKER}_Claude4ApiKeyFakeBait_${MARKER}AB
OPENAI_API_KEY=sk-proj-${MARKER}GPTApiKeyFake1234567890abcdefghij
COHERE_API_KEY=${MARKER}cohereApiKeyFakeBait1234567890abcdefghij
HUGGINGFACE_TOKEN=hf_${MARKER}fakeHuggingFaceWriteTokenBait1234
MISTRAL_API_KEY=${MARKER}MistralApiKeyFakeBait1234567890abcdef
REPLICATE_API_TOKEN=r8_${MARKER}fakeReplicateTokenBait1234567890ab
STABILITY_API_KEY=sk-${MARKER}stabilityFakeApiKey1234567890ab
TOGETHER_API_KEY=${MARKER}togetherAiApiKeyFakeBait1234567890
GROQ_API_KEY=gsk_${MARKER}fakeGroqApiKeyBaitForCanary1234
PERPLEXITY_API_KEY=pplx-${MARKER}fakePerplexityApiKey1234567890
AI21_API_KEY=${MARKER}ai21LabsApiKeyFakeBait1234567890
EOF
log "AI APIs: Anthropic + OpenAI + Cohere + HF + Mistral + Replicate + Stability + Together + Groq + Perplexity + AI21"

# ════════════════════════════════════════════════════════════════
# VERSION CONTROL: GitHub (multiple token types), GitLab, Bitbucket
# ════════════════════════════════════════════════════════════════
mkdir -p "$HOME/.config/gh"
cat > "$HOME/.config/gh/hosts.yml" <<EOF
github.com:
  user: canary-${MARKER,,}
  oauth_token: ghp_${MARKER}GitHubClassicPersonalAccessTokenBait1
  git_protocol: https
  users:
    canary-${MARKER,,}:
      oauth_token: gho_${MARKER}GitHubOAuthAppUserTokenBait12345
github.enterprise.${MARKER,,}.invalid:
  user: enterprise-user
  oauth_token: ghs_${MARKER}GitHubAppInstallationTokenBait12
EOF
# Multiple GitHub token shapes
cat > "$HOME/.github-tokens" <<EOF
# All real GitHub token formats — malware regex hits each
GH_PAT_CLASSIC=ghp_${MARKER}ClassicPATTokenBait1234567890ab
GH_PAT_FINEGRAINED=github_pat_${MARKER}_fineGrainedPersonalAccessTokenBaitForCanary11AAA22BBB
GH_APP_INSTALL=ghs_${MARKER}AppInstallationTokenBait1234567
GH_OAUTH=gho_${MARKER}OAuthAppUserTokenBait12345678901
GH_REFRESH=ghr_${MARKER}RefreshTokenBaitForCanary123456
GH_ACTIONS_RUNTIME=${MARKER}.eyJhbGciOiJSUzI1NiJ9.fakeActionsRuntimeTokenJWTBait.${MARKER}sig
EOF
echo "https://${MARKER,,}:ghp_${MARKER}gitCredentialsBait1234567890abc@github.com" > "$HOME/.git-credentials"
echo "https://gitlabuser:glpat-${MARKER}gitlabFakePersonalAccessTok@gitlab.com" >> "$HOME/.git-credentials"
echo "https://bbuser:${MARKER}BitbucketAppPasswordFakeBait@bitbucket.org" >> "$HOME/.git-credentials"
log "VCS: GitHub (PAT classic + fine-grained + OAuth + App install) + GitLab + Bitbucket"

# ════════════════════════════════════════════════════════════════
# PAYMENT: Stripe, Square, PayPal, Plaid
# ════════════════════════════════════════════════════════════════
cat > "$HOME/.payment-keys.env" <<EOF
STRIPE_SECRET_KEY=sk_live_${MARKER}StripeSecretKeyFakeBait1234567
STRIPE_PUBLISHABLE=pk_live_${MARKER}StripePublishableBait1234567890
STRIPE_RESTRICTED=rk_live_${MARKER}StripeRestrictedKeyBait12345678
STRIPE_WEBHOOK_SECRET=whsec_${MARKER}StripeWebhookSecretBait1234567
SQUARE_ACCESS_TOKEN=EAAA${MARKER}SquareAccessTokenFakeBait12345
SQUARE_APPLICATION_ID=sq0idp-${MARKER}SquareApplicationIdBait1234
PAYPAL_CLIENT_ID=A${MARKER}PayPalClientIdFakeBait1234567890ab
PAYPAL_SECRET=E${MARKER}PayPalSecretFakeBait1234567890abcdef
PLAID_CLIENT_ID=${MARKER}plaidClientIdBait1234567890ab
PLAID_SECRET=${MARKER}plaidSecretFakeBait1234567890ab1234567890
EOF
log "Payment: Stripe (multiple key types) + Square + PayPal + Plaid"

# ════════════════════════════════════════════════════════════════
# MESSAGING: Slack, Discord, Telegram, Twilio
# ════════════════════════════════════════════════════════════════
cat > "$HOME/.messaging-keys.env" <<EOF
SLACK_BOT_TOKEN=xoxb-${MARKER:0:8}-${MARKER:0:8}-fake-slack-bot-token-bait-1234
SLACK_USER_TOKEN=xoxp-${MARKER:0:8}-${MARKER:0:8}-fake-slack-user-token-bait
SLACK_APP_TOKEN=xapp-1-${MARKER}-fakeSlackAppLevelTokenBaitForCanary1234
SLACK_WEBHOOK=https://hooks.slack.com/services/T${MARKER:0:8}/B${MARKER:0:8}/${MARKER}FakeWebhookBait1234
DISCORD_BOT_TOKEN=${MARKER}.DiscFakeBait.DiscordBotTokenFakeBaitForCanaryAttackSim
DISCORD_WEBHOOK=https://discord.com/api/webhooks/${MARKER:0:10}/${MARKER}fakeDiscordWebhookBait
TELEGRAM_BOT_TOKEN=1234567890:${MARKER}TelegramBotTokenFakeBait1234
TWILIO_ACCOUNT_SID=AC${MARKER}TwilioAccountSidFakeBait12345
TWILIO_AUTH_TOKEN=${MARKER}TwilioAuthTokenFakeBait12345678
TWILIO_API_KEY_SID=SK${MARKER}TwilioApiKeySidBait1234567890
TWILIO_API_KEY_SECRET=${MARKER}TwilioApiKeySecretBait1234567890
EOF
log "Messaging: Slack (bot+user+app+webhook) + Discord + Telegram + Twilio"

# ════════════════════════════════════════════════════════════════
# EMAIL: SendGrid, Mailgun, Postmark, AWS SES
# ════════════════════════════════════════════════════════════════
cat > "$HOME/.email-keys.env" <<EOF
SENDGRID_API_KEY=SG.${MARKER}sendgridApiKey.fakeBaitForCanaryAttackSim1234567890ab
MAILGUN_API_KEY=key-${MARKER}mailgunApiKeyFakeBait12345678901
MAILGUN_DOMAIN=mg.${MARKER,,}.invalid
POSTMARK_TOKEN=${MARKER}-postmark-server-api-token-bait
MANDRILL_API_KEY=md_${MARKER}mandrillApiKeyFakeBait1234567
EOF
log "Email: SendGrid + Mailgun + Postmark + Mandrill"

# ════════════════════════════════════════════════════════════════
# PACKAGE REGISTRIES: npm, PyPI, RubyGems, Cargo, Maven, Docker Hub
# ════════════════════════════════════════════════════════════════
cat > "$HOME/.npmrc" <<EOF
//registry.npmjs.org/:_authToken=npm_${MARKER}npmAutomationTokenFakeBait1234
//registry.npmjs.org/:_password=${MARKER}base64EncodedNpmPasswordBait
//npm.fontawesome.com/:_authToken=${MARKER}fontawesomeProTokenBait
@private-org:registry=https://registry.npmjs.org/
always-auth=true
EOF
mkdir -p "$HOME/.config/pip"
cat > "$HOME/.config/pip/pip.conf" <<EOF
[global]
extra-index-url = https://pypi-${MARKER,,}:${MARKER}PyPIPersonalAccessTokenBait@pypi.${MARKER,,}.invalid/
EOF
cat > "$HOME/.pypirc" <<EOF
[pypi]
username = __token__
password = pypi-${MARKER}AgEIcHlwaS5vcmcCJDFmZjVjZWQwLTVl${MARKER}FakePypiUploadTokenBait1234567890ab
EOF
echo ":rubygems_api_key: rubygems_${MARKER}RubyGemsApiKeyFakeBait1234567890ab" > "$HOME/.gem/credentials" 2>/dev/null || \
    { mkdir -p "$HOME/.gem" && echo ":rubygems_api_key: rubygems_${MARKER}RubyGemsApiKeyFakeBait1234567890ab" > "$HOME/.gem/credentials"; }
chmod 600 "$HOME/.gem/credentials" 2>/dev/null
mkdir -p "$HOME/.cargo"
cat > "$HOME/.cargo/credentials.toml" <<EOF
[registry]
token = "${MARKER}cargoCratesIoApiTokenFakeBait1234"
EOF
log "Package registries: npm + PyPI + RubyGems + Cargo (+ Docker Hub above)"

# ════════════════════════════════════════════════════════════════
# DATA: HashiCorp Vault, MongoDB Atlas, Redis Labs, Snowflake,
#       Databricks, Datadog, NewRelic
# ════════════════════════════════════════════════════════════════
cat > "$HOME/.data-keys.env" <<EOF
VAULT_TOKEN=hvs.${MARKER}vaultRootOrServiceTokenFakeBait1234567890abcdefghi
VAULT_ADDR=https://vault.${MARKER,,}.invalid:8200
CONSUL_HTTP_TOKEN=${MARKER}-1234-5678-9abc-def012345678
NOMAD_TOKEN=${MARKER}-nomad-1234-5678-9abc-def0
MONGODB_ATLAS_PUBLIC_KEY=${MARKER}MongoAtlasPubKeyBait12
MONGODB_ATLAS_PRIVATE_KEY=${MARKER}-MongoAtlasPrivateKeyFakeBait-1234-5678
SNOWFLAKE_ACCOUNT=${MARKER,,}.snowflakecomputing.com
SNOWFLAKE_USER=canary_bait
SNOWFLAKE_PASSWORD=${MARKER}SnowflakePasswordFakeBait1234
DATABRICKS_TOKEN=dapi${MARKER}DatabricksTokenFakeBait1234567890ab
DATABRICKS_HOST=https://${MARKER,,}.cloud.databricks.com
DD_API_KEY=${MARKER}datadogApiKeyFakeBait1234567890ab
DD_APP_KEY=${MARKER}datadogAppKeyFakeBait12345678901234567890ab
NEW_RELIC_LICENSE_KEY=${MARKER}NRAL-NewRelicLicenseKeyFakeBait12345
NEW_RELIC_USER_KEY=NRAK-${MARKER}NewRelicUserApiKeyFakeBait12
SENTRY_AUTH_TOKEN=${MARKER}sentryAuthTokenFakeBait1234567890abcdef
EOF
log "Data: Vault + Consul + Nomad + MongoDB Atlas + Snowflake + Databricks + Datadog + NewRelic + Sentry"

# ════════════════════════════════════════════════════════════════
# DATABASES: connection strings with embedded passwords
# ════════════════════════════════════════════════════════════════
cat > "$HOME/.db-conn-strings.env" <<EOF
DATABASE_URL=postgres://app_user:${MARKER}PostgresPasswordBait@db.${MARKER,,}.invalid:5432/production
MYSQL_URL=mysql://root:${MARKER}MySQLRootPasswordBait@mysql.${MARKER,,}.invalid:3306/main
REDIS_URL=redis://default:${MARKER}RedisPasswordBait@redis.${MARKER,,}.invalid:6379
MONGODB_URI=mongodb://app:${MARKER}MongoPasswordBait@mongo.${MARKER,,}.invalid:27017/prod
ELASTICSEARCH_URL=https://elastic:${MARKER}ElasticPasswordBait@es.${MARKER,,}.invalid:9200
RABBITMQ_URL=amqp://app:${MARKER}RabbitMQPasswordBait@rabbit.${MARKER,,}.invalid:5672/
CASSANDRA_PASSWORD=${MARKER}CassandraSuperuserPasswordBait
EOF
log "DBs: PG + MySQL + Redis + Mongo + ES + RabbitMQ + Cassandra (embedded creds)"

# ════════════════════════════════════════════════════════════════
# 1Password / Bitwarden / LastPass CLI configs
# ════════════════════════════════════════════════════════════════
mkdir -p "$HOME/.config/op"
cat > "$HOME/.config/op/config" <<EOF
{
  "latest_signin": "${MARKER}-fake-account",
  "device": "${MARKER}-fake-device-uuid",
  "accounts": [{
    "shorthand": "canary-shorthand",
    "url": "https://${MARKER,,}-fake.1password.com",
    "email": "canary-bait@${MARKER,,}.invalid",
    "accountUUID": "${MARKER}FAKEACCT001",
    "userUUID": "${MARKER}FAKEUSER001"
  }]
}
EOF
mkdir -p "$HOME/.config/Bitwarden\ CLI"
cat > "$HOME/.config/Bitwarden\ CLI/data.json" <<EOF
{
  "userEmail": "canary@${MARKER,,}.invalid",
  "accessToken": "${MARKER}.bitwardenAccessTokenFakeBait.${MARKER}sig",
  "refreshToken": "${MARKER}BitwardenRefreshTokenFakeBait1234567890",
  "kdfIterations": 600000
}
EOF
log "Password managers: 1Password + Bitwarden CLI configs"

# ════════════════════════════════════════════════════════════════
# SSH KEYS: ed25519, RSA-4096, RSA-2048, ECDSA-256, ECDSA-521
# (every major modern key type — real malware enumerates them all)
# ════════════════════════════════════════════════════════════════
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
for keytype in "ed25519:" "rsa:-b 4096" "rsa_2048:-b 2048"; do
    name="${keytype%%:*}"
    args="${keytype##*:}"
    keyfile="$HOME/.ssh/id_${name}"
    if [ ! -f "$keyfile" ]; then
        case "$name" in
            rsa_2048)
                ssh-keygen -t rsa -b 2048 -N "" \
                    -C "${MARKER}-bait-rsa2048@xhelix-test" \
                    -f "$keyfile" >/dev/null 2>&1
                ;;
            rsa)
                ssh-keygen -t rsa -b 4096 -N "" \
                    -C "${MARKER}-bait-rsa4096@xhelix-test" \
                    -f "$keyfile" >/dev/null 2>&1
                ;;
            *)
                ssh-keygen -t "$name" -N "" \
                    -C "${MARKER}-bait-${name}@xhelix-test" \
                    -f "$keyfile" >/dev/null 2>&1
                ;;
        esac
        chmod 600 "$keyfile" 2>/dev/null
    fi
done
# ECDSA P-256 + P-521
ssh-keygen -t ecdsa -b 256 -N "" -C "${MARKER}-ecdsa256@xhelix" \
    -f "$HOME/.ssh/id_ecdsa" >/dev/null 2>&1 || true
ssh-keygen -t ecdsa -b 521 -N "" -C "${MARKER}-ecdsa521@xhelix" \
    -f "$HOME/.ssh/id_ecdsa_521" >/dev/null 2>&1 || true
chmod 600 "$HOME/.ssh/id_ecdsa" "$HOME/.ssh/id_ecdsa_521" 2>/dev/null
# SSH config with embedded ProxyCommand secrets
cat > "$HOME/.ssh/config" <<EOF
Host prod-bastion
    HostName bastion.${MARKER,,}.invalid
    User canary-admin
    IdentityFile ~/.ssh/id_ed25519
    ProxyCommand ssh -W %h:%p -i ~/.ssh/id_rsa jump@${MARKER,,}.invalid

Host *
    AddKeysToAgent yes
    ServerAliveInterval 30
EOF
log "SSH: ed25519 + RSA-4096 + RSA-2048 + ECDSA-256 + ECDSA-521 (all fresh, never deployed) + ~/.ssh/config"

# ════════════════════════════════════════════════════════════════
# TLS / X.509 (real format, generated fresh)
# ════════════════════════════════════════════════════════════════
if command -v openssl >/dev/null 2>&1; then
    if [ "$EUID" -eq 0 ]; then
        mkdir -p /etc/ssl/private-canary
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout /etc/ssl/private-canary/server.key \
            -out /etc/ssl/private-canary/server.crt \
            -days 365 -subj "/CN=${MARKER,,}.canary.invalid" >/dev/null 2>&1 || true
        chmod 600 /etc/ssl/private-canary/server.key 2>/dev/null
        log "TLS: /etc/ssl/private-canary/{server.key, server.crt} (fresh self-signed)"
    fi
fi

# ════════════════════════════════════════════════════════════════
# GPG / age / encryption private keys
# ════════════════════════════════════════════════════════════════
cat > "$HOME/.age-key" <<EOF
# created: 2026-01-01T00:00:00Z
# public key: age1${MARKER,,}fakeAgePublicKey1234567890ab
AGE-SECRET-KEY-${MARKER}1FAKEAGESECRETKEYBAITCANARYXHELIXATTACKSIM12345678901234
EOF
chmod 600 "$HOME/.age-key"
log "Encryption: ~/.age-key (age private key format)"

# ════════════════════════════════════════════════════════════════
# JWT signing secrets / app secrets
# ════════════════════════════════════════════════════════════════
cat > "$HOME/.app-secrets.env" <<EOF
JWT_SECRET=${MARKER}-256-bit-hmac-secret-for-jwt-signing-bait-1234567890abcdef
COOKIE_SECRET=${MARKER}-fake-express-cookie-signing-secret-bait
ENCRYPTION_KEY=${MARKER}-32-byte-symmetric-encryption-key-bait-fake!
RAILS_MASTER_KEY=${MARKER}-rails-master-key-credentials-bait
DJANGO_SECRET_KEY=${MARKER}-django-50char-secret-key-for-cryptographic-signing-bait
PHP_APP_KEY=base64:${MARKER}fakeLaravelApplicationEncryptionKeyBait==
NEXTAUTH_SECRET=${MARKER}-nextauth-jwt-encryption-secret-bait-32
SESSION_SECRET=${MARKER}-flask-secret-key-for-session-cookies-bait
EOF
log "App secrets: JWT + cookie + encryption + Rails/Django/Laravel/Next/Flask master keys"

# ════════════════════════════════════════════════════════════════
# /var/www tenant .env files (multi-tenant Plesk realism)
# ════════════════════════════════════════════════════════════════
if [ "$EUID" -eq 0 ]; then
    for tenant in tenant-a tenant-b tenant-c; do
        d="/var/www/${tenant}"
        mkdir -p "$d"
        cat > "$d/.env" <<EOF
APP_ENV=production
DATABASE_URL=postgres://${tenant}:${MARKER}_${tenant}_pgpass@db.example.com:5432/${tenant}_prod
STRIPE_SECRET_KEY=sk_live_${MARKER}${tenant}StripeSecretKeyFake
JWT_SECRET=${MARKER}${tenant}JwtSigningSecretFakeBait
AWS_ACCESS_KEY_ID=AKIA${MARKER:0:12}TN
AWS_SECRET_ACCESS_KEY=${MARKER}${tenant}awsSecretAccessKeyFake
SENDGRID_API_KEY=SG.${MARKER}.${tenant}sendgridFake
EOF
    done
    log "Tenants: /var/www/tenant-{a,b,c}/.env (multi-tenant Plesk realism)"
fi

# ════════════════════════════════════════════════════════════════
# Shell history with EXPORT leak patterns
# ════════════════════════════════════════════════════════════════
cat > "$HOME/.bash_history" <<EOF
ls
cd /var/www
export AWS_ACCESS_KEY_ID=AKIA${MARKER:0:12}HI
export AWS_SECRET_ACCESS_KEY=${MARKER}commandHistoryLeakPattern
aws s3 ls
psql -U admin -h db.example.com -d production
export GITHUB_TOKEN=ghp_${MARKER}exportedInHistoryFileBait1
export ANTHROPIC_API_KEY=sk-ant-api03-${MARKER}_inHistoryFile
git push origin main
docker login -u canary -p ${MARKER}dockerPasswordLeakedHistory
kubectl config set-credentials admin --token=${MARKER}.k8sTokenLeakedInHistory
gh auth login --with-token < /tmp/gh.token
EOF
cat > "$HOME/.zsh_history" <<EOF
: 1700000000:0;export STRIPE_SECRET_KEY=sk_live_${MARKER}zshHistoryLeakedStripeFake
: 1700000001:0;ssh -i ~/.ssh/id_rsa root@bastion.example.com
: 1700000002:0;curl -H "Authorization: Bearer ${MARKER}-zsh-leaked-bearer-token" https://api.example.com/v1/admin
EOF
log "Shell history: ~/.bash_history + ~/.zsh_history (export-pattern leaks)"

# ════════════════════════════════════════════════════════════════
# AWS IMDS canary (if user wants to test IMDS-blocking too)
# ════════════════════════════════════════════════════════════════
# Nothing to seed here — IMDS lives at 169.254.169.254 and is
# attacker-discovered. Real malware fetches it; xhelix should see
# the outbound connect attempt.

log ""
log "═══════════════════════════════════════════════════════════════"
log "=== seed complete. ~50 credential paths planted. ==="
log "Marker embedded in every value: $MARKER"
log "Categories:"
log "  Cloud:        AWS (3 profiles), GCP (ADC+SA), Azure (3 files), DO, Linode, Hetzner, Vultr, Cloudflare"
log "  Containers:   Docker (4 registries), K8s (multi-cluster)"
log "  AI APIs:      Anthropic, OpenAI, Cohere, HuggingFace, Mistral, Replicate, Stability, Together, Groq, Perplexity, AI21"
log "  VCS:          GitHub (5 token types), GitLab, Bitbucket"
log "  Payment:      Stripe (4), Square, PayPal, Plaid"
log "  Messaging:    Slack (4), Discord, Telegram, Twilio (4)"
log "  Email:        SendGrid, Mailgun, Postmark, Mandrill"
log "  Pkg reg:      npm, PyPI, RubyGems, Cargo"
log "  Data:         Vault, Consul, Nomad, MongoDB Atlas, Snowflake, Databricks, Datadog, NewRelic, Sentry"
log "  DB conn:      PG, MySQL, Redis, Mongo, ES, RabbitMQ, Cassandra"
log "  Pass mgr:     1Password, Bitwarden"
log "  SSH:          ed25519, RSA-4096, RSA-2048, ECDSA-256, ECDSA-521"
log "  TLS/Crypto:   self-signed cert/key, age private key"
log "  App secrets:  JWT, Cookie, Rails, Django, Laravel, Next, Flask"
log "  Tenants:      /var/www/tenant-{a,b,c}/.env (if root)"
log "  History:      ~/.bash_history + ~/.zsh_history with export leaks"
log "═══════════════════════════════════════════════════════════════"
