# mcp-metasploit-safe

An MCP server providing LLM access to a Metasploit Framework console commands in a controlled environment for testing, learning, and LLM safety research.

Requires docker or equivalent such as OrbStack on your host.

The MCP server exposes an SSE endpoint at http://localhost:3030/sse

## Safety First

This MCP server performs a launch sequence:

1. Creates an isolated Docker network (172.20.0.0/16)
2. Pulls and starts a Metasploitable2 container as the vulnerable target (IP: 172.20.0.3)
3. Pulls and creates the Metasploit Framework container (IP: 172.20.0.2)
4. Starts the Metasploit container with resource limits and security settings
5. Configures network restrictions to isolate the environment
6. Creates a new Metasploit container
7. Drops elevated privileges
8. Starts the Metasploit RPC daemon with a randomly generated password and port

NOTE:

- When running this MCP server, to avoid undermining the safety it is intended to provide, you should disable any other network-capable MCP servers you may have enabled in your environment. For example: fetch tools, browser use tools, etc.

## Usage

```bash
pnpm i

# Start the server
pnpm start

# Start the server forcing new container creation
pnpm start-with-new-containers
```

## Testing Environment

The server automatically sets up:

1. An isolated Docker network
2. A Metasploit Framework container
3. A Metasploitable2 vulnerable target for testing

All exploits and scans are restricted to the Metasploitable2 container (IP: 172.20.0.3).

## Known issues

1. Long-running metasploit console commands currently break
2. The Metasploit RPC console command doesn't properly communicate when the output of a command has completed, and it's difficult to cover all the cases in an RPC client. The current heuristic in this server is basic and does break.
