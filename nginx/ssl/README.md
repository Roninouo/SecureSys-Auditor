# TLS certificates for docker-compose.prod

Place TLS certificate files here for NGINX to terminate HTTPS.

Required filenames:
- `fullchain.pem`
- `privkey.pem`

These files should be provisioned by your certificate automation (ACME/Let's Encrypt) and **must not** be committed to git.
