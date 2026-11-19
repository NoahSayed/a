# agent-bridge relay. Build from the agent-bridge directory:
#   docker build -f relay/Dockerfile -t agent-bridge-relay .
# Run (the data volume holds the SQLite database; back it up by copying relay.db):
#   docker run -d --name relay -p 8787:8787 -v relay-data:/data \
#     -e RELAY_ADMIN_KEY="$(openssl rand -hex 32)" agent-bridge-relay
# The relay has no npm dependencies: it uses only Node's built-in modules.
FROM node:22-alpine

WORKDIR /app
COPY package.json relay.js relay-audit.js store.js ./
COPY stores/ ./stores/

# Non-root user; /data is the only writable place.
RUN mkdir -p /data && chown node:node /data
USER node

ENV NODE_ENV=production \
    RELAY_HOST=0.0.0.0 \
    RELAY_PORT=8787 \
    RELAY_DB=/data/relay.db
VOLUME /data
EXPOSE 8787

# /healthz needs no key and returns {"status":"ok"} only. (With RELAY_TLS_CA, i.e. mutual TLS, the
# probe has no client certificate and fails: start the container with --no-healthcheck then.)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require(process.env.RELAY_TLS_CERT?'https':'http').get({host:'127.0.0.1',port:process.env.RELAY_PORT,path:'/healthz',rejectUnauthorized:false},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "relay.js"]
