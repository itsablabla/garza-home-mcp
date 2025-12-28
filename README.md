# Garza Home MCP

GARZA OS Home MCP Server - Personal/home automation integrations.

## Services

| Service | Tools | Description |
|---------|-------|-------------|
| Beeper | 10 | Unified messaging (search, send, archive, reminders) |
| Abode | 9 | Home security (mode, devices, locks, automations) |
| UniFi | 18 | Cameras, lights, sensors, PTZ, snapshots, events |
| ProtonMail | 4 | Email search, read, send, folders |
| Graphiti | 3 | Knowledge graph (search, facts, episodes) |
| Bible | 3 | VOTD, passages, search |
| Pushcut | 1 | Push notifications |

**Total: 49 tools**

## Deployment

Deployed on Fly.io (Denver region): `https://garza-home-mcp.fly.dev`

### Health Check
```
GET /health
```

### MCP Endpoint
```
POST /sse?key={API_KEY}
POST /mcp?key={API_KEY}
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| MCP_API_KEY | API key for authentication |
| BEEPER_TOKEN | Beeper API token |
| ABODE_USER / ABODE_PASS | Abode credentials |
| UNIFI_HOST / UNIFI_USER / UNIFI_PASS | UniFi Protect |
| PROTON_USER / PROTON_PASS / PROTON_BRIDGE | ProtonMail IMAP |
| GRAPHITI_URL | Graphiti endpoint |
| BIBLE_API_KEY | Scripture API key |
| PUSHCUT_KEY | Pushcut notification key |

## Claude.ai MCP Configuration

```json
{
  "name": "Garza Home MCP",
  "url": "https://garza-home-mcp.fly.dev/sse?key=YOUR_API_KEY"
}
```

## Development

```bash
npm install
npm start
```

## License

MIT - Jaden Garza
