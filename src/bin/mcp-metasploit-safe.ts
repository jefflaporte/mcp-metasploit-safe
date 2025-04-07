#!/usr/bin/env node

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import { execa } from 'execa'
import path from 'path'

await yargs(hideBin(process.argv))
  .scriptName('mcp-metasploit-safe')
  // Simply start the mcp-metasploit-safe server in production mode
  .command(
    'start',
    'Start the mcp-metasploit-safe server',
    () => {},
    async () => {
      try {
        const serverPath = path.resolve(__dirname, '../../src/mcp-metasploit-safe.ts');
        console.log(`Starting mcp-metasploit-safe server from: ${serverPath}`);
        await execa('node', [serverPath], { stdio: 'inherit' });
      } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
      }
    })
  .help()
  .parse()
