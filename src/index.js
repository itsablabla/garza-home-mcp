// Garza Home MCP v3.9 - Fixed Beeper Intel column names (chat_id, content)
const BEEPER_BRIDGE_URL = "https://beeper-bridge.garzahive.com";
const CC_MCP_URL = "https://computer-use-mcp.garzahive.com/direct";
const CC_MCP_KEY = "computeruse2024garzahive";
const PROTONMAIL_URL = "https://protonmail-proxy.garzahive.com/direct";
const BIBLE_API_URL = "https://bible-api.com";
const SUPABASE_URL = "https://vbwhhmdudzigolwhklal.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZid2hobWR1ZHppZ29sd2hrbGFsIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2NjY5MTUyMiwiZXhwIjoyMDgyMjY3NTIyfQ.rzwf0GXU49Y6w5Z6AET8pdlmwt6YgeNLslJ3tJOjpg8";

const TOOLS = [
  { name: "ping", description: "Health check", inputSchema: { type: "object", properties: {}, required: [] } },
  // Beeper Intelligence
  { name: "beeper_search_history", description: "Search message history across all Beeper conversations", inputSchema: { type: "object", properties: { query: { type: "string", description: "Search text" }, chat_id: { type: "string", description: "Optional: filter by chat ID" }, limit: { type: "number", description: "Max results (default 20)" } }, required: ["query"] } },
  { name: "beeper_recent_messages", description: "Get recent messages from a chat room", inputSchema: { type: "object", properties: { chat_id: { type: "string", description: "Chat ID" }, limit: { type: "number", description: "Max results (default 50)" } }, required: ["chat_id"] } },
  { name: "beeper_list_chats", description: "List all synced Beeper chats", inputSchema: { type: "object", properties: { limit: { type: "number" } }, required: [] } },
  { name: "beeper_voice_memos", description: "List voice memos from Beeper", inputSchema: { type: "object", properties: { chat_id: { type: "string" }, limit: { type: "number" } }, required: [] } },
  { name: "beeper_chat_stats", description: "Get message statistics for chats", inputSchema: { type: "object", properties: {}, required: [] } },
  // Graphiti
  { name: "graphiti_search", description: "Search knowledge graph", inputSchema: { type: "object", properties: { query: { type: "string" }, limit: { type: "number" } }, required: ["query"] } },
  { name: "graphiti_add_episode", description: "Add episode to knowledge graph", inputSchema: { type: "object", properties: { name: { type: "string" }, content: { type: "string" }, source: { type: "string" } }, required: ["name", "content"] } },
  { name: "graphiti_get_facts", description: "Get facts from knowledge graph", inputSchema: { type: "object", properties: { entity: { type: "string" } }, required: [] } },
  // Abode Security
  { name: "abode_list_devices", description: "List all Abode devices", inputSchema: { type: "object", properties: {}, required: [] } },
  { name: "abode_get_mode", description: "Get current Abode alarm mode", inputSchema: { type: "object", properties: {}, required: [] } },
  { name: "abode_set_mode", description: "Set Abode alarm mode", inputSchema: { type: "object", properties: { mode: { type: "string", enum: ["standby", "home", "away"] } }, required: ["mode"] } },
  { name: "abode_lock_device", description: "Lock/unlock device", inputSchema: { type: "object", properties: { device_id: { type: "string" }, lock: { type: "boolean" } }, required: ["device_id", "lock"] } },
  // Beeper Bridge
  { name: "beeper_get_accounts", description: "List connected messaging accounts", inputSchema: { type: "object", properties: {}, required: [] } },
  { name: "beeper_search", description: "Search chats and messages", inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] } },
  { name: "beeper_search_chats", description: "Search chats by title or participants", inputSchema: { type: "object", properties: { query: { type: "string" }, scope: { type: "string", enum: ["titles", "participants"] }, type: { type: "string", enum: ["single", "group", "any"] }, limit: { type: "number" } }, required: [] } },
  { name: "beeper_search_messages", description: "Search messages across chats", inputSchema: { type: "object", properties: { query: { type: "string" }, chatIDs: { type: "array" }, dateAfter: { type: "string" }, dateBefore: { type: "string" }, limit: { type: "number" } }, required: [] } },
  { name: "beeper_get_chat", description: "Get chat details", inputSchema: { type: "object", properties: { chatID: { type: "string" } }, required: ["chatID"] } },
  { name: "beeper_list_messages", description: "List messages from a chat", inputSchema: { type: "object", properties: { chatID: { type: "string" }, cursor: { type: "string" } }, required: ["chatID"] } },
  { name: "beeper_send_message", description: "Send a message", inputSchema: { type: "object", properties: { chatID: { type: "string" }, text: { type: "string" } }, required: ["chatID", "text"] } },
  // ProtonMail
  { name: "search_protonmail", description: "Search ProtonMail inbox", inputSchema: { type: "object", properties: { criteria: { type: "string" }, limit: { type: "number" } }, required: [] } },
  { name: "read_protonmail", description: "Read email by UID", inputSchema: { type: "object", properties: { uid: { type: "number" } }, required: ["uid"] } },
  { name: "send_protonmail", description: "Send email", inputSchema: { type: "object", properties: { to: { type: "string" }, subject: { type: "string" }, body: { type: "string" } }, required: ["to", "subject", "body"] } },
  // Bible
  { name: "bible_votd", description: "Verse of the day", inputSchema: { type: "object", properties: {}, required: [] } },
  { name: "bible_passage", description: "Get Bible passage", inputSchema: { type: "object", properties: { reference: { type: "string" } }, required: ["reference"] } },
  { name: "bible_search", description: "Search Bible", inputSchema: { type: "object", properties: { query: { type: "string" } }, required: ["query"] } },
];

const BEEPER_INTEL_TOOLS = ["beeper_search_history", "beeper_recent_messages", "beeper_list_chats", "beeper_voice_memos", "beeper_chat_stats"];
const GRAPHITI_TOOLS = ["graphiti_search", "graphiti_add_episode", "graphiti_get_facts"];
const BEEPER_TOOLS = ["beeper_get_accounts", "beeper_search", "beeper_search_chats", "beeper_search_messages", "beeper_get_chat", "beeper_list_messages", "beeper_send_message"];
const ABODE_TOOLS = ["abode_list_devices", "abode_get_mode", "abode_set_mode", "abode_lock_device"];
const PROTONMAIL_TOOLS = ["search_protonmail", "read_protonmail", "send_protonmail"];
const BIBLE_TOOLS = ["bible_votd", "bible_passage", "bible_search"];

async function supabaseQuery(endpoint, params = {}) {
  const url = new URL(`${SUPABASE_URL}/rest/v1/${endpoint}`);
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  const res = await fetch(url.toString(), {
    headers: { "apikey": SUPABASE_ANON_KEY, "Authorization": `Bearer ${SUPABASE_ANON_KEY}` }
  });
  if (!res.ok) return { error: `Supabase error: ${res.status}` };
  return await res.json();
}

async function executeBeeperIntel(name, args) {
  switch (name) {
    case "beeper_search_history": {
      const limit = args.limit || 20;
      let params = { content: `ilike.*${args.query}*`, order: "timestamp.desc", limit: String(limit) };
      if (args.chat_id) params.chat_id = `eq.${args.chat_id}`;
      return await supabaseQuery("beeper_messages", params);
    }
    case "beeper_recent_messages": {
      const limit = args.limit || 50;
      return await supabaseQuery("beeper_messages", { chat_id: `eq.${args.chat_id}`, order: "timestamp.desc", limit: String(limit) });
    }
    case "beeper_list_chats": {
      const limit = args.limit || 50;
      return await supabaseQuery("beeper_chats", { order: "last_message_at.desc", limit: String(limit) });
    }
    case "beeper_voice_memos": {
      const limit = args.limit || 20;
      let params = { is_voice_memo: "eq.true", order: "timestamp.desc", limit: String(limit) };
      if (args.chat_id) params.chat_id = `eq.${args.chat_id}`;
      return await supabaseQuery("beeper_messages", params);
    }
    case "beeper_chat_stats": {
      return await supabaseQuery("beeper_chats", { order: "last_message_at.desc", limit: "20", select: "*" });
    }
  }
  return { error: "Unknown tool" };
}

async function callProxy(url, tool, args, apiKey) {
  try {
    const headers = { "Content-Type": "application/json" };
    if (apiKey) headers["X-API-Key"] = apiKey;
    const res = await fetch(url, { method: "POST", headers, body: JSON.stringify({ tool, arguments: args || {} }) });
    if (!res.ok) return { error: `Proxy error: ${res.status}` };
    return await res.json();
  } catch (e) { return { error: e.message }; }
}

const GRAPHITI_URL = "https://graphiti.garzahive.com";
async function executeGraphiti(name, args) {
  switch (name) {
    case "graphiti_search": return await callProxy(GRAPHITI_URL, "search", args);
    case "graphiti_add_episode": return await callProxy(GRAPHITI_URL, "add_episode", args);
    case "graphiti_get_facts": return await callProxy(GRAPHITI_URL, "get_facts", args);
  }
  return { error: "Unknown tool" };
}

const VOTD_REFS = ["John 3:16", "Jeremiah 29:11", "Psalm 23:1-6", "Romans 8:28", "Philippians 4:13", "Isaiah 41:10", "Proverbs 3:5-6"];
async function executeBible(name, args) {
  const t = args.translation || "web";
  switch (name) {
    case "bible_votd": {
      const day = Math.floor((Date.now() - new Date(new Date().getFullYear(), 0, 0)) / 86400000);
      const ref = VOTD_REFS[day % VOTD_REFS.length];
      const res = await fetch(`${BIBLE_API_URL}/${encodeURIComponent(ref)}?translation=${t}`);
      return res.ok ? await res.json() : { error: `API error: ${res.status}` };
    }
    case "bible_passage": {
      const res = await fetch(`${BIBLE_API_URL}/${encodeURIComponent(args.reference)}?translation=${t}`);
      return res.ok ? await res.json() : { error: `API error: ${res.status}` };
    }
    case "bible_search": {
      const res = await fetch(`${BIBLE_API_URL}/${encodeURIComponent(args.query)}?translation=${t}`);
      return res.ok ? await res.json() : { error: `API error: ${res.status}` };
    }
  }
  return { error: "Unknown tool" };
}

async function executeTool(name, args, env) {
  if (name === "ping") return { pong: true, timestamp: new Date().toISOString(), version: "3.9" };
  if (BEEPER_INTEL_TOOLS.includes(name)) return await executeBeeperIntel(name, args);
  if (GRAPHITI_TOOLS.includes(name)) return await executeGraphiti(name, args);
  if (BIBLE_TOOLS.includes(name)) return await executeBible(name, args);
  if (BEEPER_TOOLS.includes(name)) return await callProxy(BEEPER_BRIDGE_URL, name.replace("beeper_", ""), args);
  if (ABODE_TOOLS.includes(name)) return await callProxy(CC_MCP_URL, name, args, CC_MCP_KEY);
  if (PROTONMAIL_TOOLS.includes(name)) return await callProxy(PROTONMAIL_URL, name, args, CC_MCP_KEY);
  return { error: `Unknown tool: ${name}` };
}

const corsHeaders = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization" };

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
    const url = new URL(request.url);
    if (url.pathname === "/health") return Response.json({ status: "ok", version: "3.9" }, { headers: corsHeaders });
    if (request.method === "GET" && url.pathname === "/") {
      return Response.json({ name: "Garza Home MCP", version: "3.9", tools: TOOLS.map(t => t.name) }, { headers: corsHeaders });
    }
    if (request.method === "POST") {
      try {
        const body = await request.json();
        if (body.method === "tools/list") {
          return Response.json({ jsonrpc: "2.0", id: body.id, result: { tools: TOOLS } }, { headers: corsHeaders });
        }
        if (body.method === "tools/call") {
          const { name, arguments: args } = body.params;
          const result = await executeTool(name, args || {}, env);
          return Response.json({ jsonrpc: "2.0", id: body.id, result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] } }, { headers: corsHeaders });
        }
      } catch (e) {
        return Response.json({ error: e.message }, { status: 400, headers: corsHeaders });
      }
    }
    return Response.json({ error: "Not found" }, { status: 404, headers: corsHeaders });
  }
};
