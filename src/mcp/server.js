// src/mcp/server.js
// Zero-dependency Model Context Protocol (MCP) Server for WebCrypt
// PuterVision Standard - stdio JSON-RPC 2.0 transport

import { WEBCRYPT_MCP_TOOLS } from "./tools.js";
import { handleToolCall } from "./handlers.js";

export class WebCryptMCPServer {
  constructor(options = {}) {
    this.name = "webcrypt";
    this.version = "1.0.0";
    this.tools = WEBCRYPT_MCP_TOOLS;
    this.in = options.stdin || process.stdin;
    this.out = options.stdout || process.stdout;
  }

  async handleMessage(message) {
    if (!message || typeof message !== "object") return null;
    const { id, method, params } = message;

    // Handle notifications (no id)
    if (id === undefined || id === null) {
      if (method === "notifications/initialized") {
        // Initialization acknowledged
        return null;
      }
      return null;
    }

    try {
      switch (method) {
        case "initialize": {
          return {
            jsonrpc: "2.0",
            id,
            result: {
              protocolVersion: "2024-11-05",
              capabilities: {
                tools: {},
              },
              serverInfo: {
                name: this.name,
                version: this.version,
              },
            },
          };
        }

        case "ping": {
          return {
            jsonrpc: "2.0",
            id,
            result: {},
          };
        }

        case "tools/list": {
          return {
            jsonrpc: "2.0",
            id,
            result: {
              tools: this.tools,
            },
          };
        }

        case "tools/call": {
          const toolName = params?.name;
          const toolArgs = params?.arguments || {};
          const result = await handleToolCall(toolName, toolArgs);
          return {
            jsonrpc: "2.0",
            id,
            result: {
              content: [
                {
                  type: "text",
                  text: typeof result === "string" ? result : JSON.stringify(result, null, 2),
                },
              ],
            },
          };
        }

        default: {
          return {
            jsonrpc: "2.0",
            id,
            error: {
              code: -32601,
              message: `Method not found: ${method}`,
            },
          };
        }
      }
    } catch (err) {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            {
              type: "text",
              text: `Error: ${err.message || String(err)}`,
            },
          ],
          isError: true,
        },
      };
    }
  }

  send(response) {
    if (!response) return;
    const json = JSON.stringify(response);
    this.out.write(`${json}\n`);
  }

  start() {
    let buffer = "";

    // Handle stream errors gracefully (e.g. EPIPE on abrupt client disconnect)
    if (typeof this.in.on === "function") this.in.on("error", () => {});
    if (typeof this.out.on === "function") this.out.on("error", () => {});

    this.in.on("data", async chunk => {
      buffer += chunk.toString("utf-8");

      while (true) {
        const lineEnd = buffer.indexOf("\n");
        if (lineEnd === -1) break;

        const line = buffer.slice(0, lineEnd).trim();
        buffer = buffer.slice(lineEnd + 1);

        if (line.length === 0) continue;

        try {
          const message = JSON.parse(line);
          const response = await this.handleMessage(message);
          if (response) {
            this.send(response);
          }
        } catch (parseErr) {
          this.send({
            jsonrpc: "2.0",
            id: null,
            error: {
              code: -32700,
              message: `Parse error: ${parseErr.message}`,
            },
          });
        }
      }
    });

    this.in.on("end", () => {
      // Stream ended
    });
  }
}

export function startMCPServer() {
  const server = new WebCryptMCPServer();
  server.start();
  return server;
}
