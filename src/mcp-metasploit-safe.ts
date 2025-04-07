import type { CreateMessageRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import {
    FastMCP,
    type FastMCPSession,
    type Progress,
    type ContentResult,
    type TextContent,
    type ImageContent,
} from 'fastmcp'
import { z } from 'zod'
import chalk from 'chalk'
import crypto from 'node:crypto'
import Docker from 'dockerode'
import MsfRpcClient from 'msfrpc'

const IMAGE_METASPLOIT = 'metasploitframework/metasploit-framework:latest'
const IMAGE_METASPLOITABLE = 'tleemcjr/metasploitable2:latest'
const SLOW_RESPONSE_MODE: 'sampling' | 'progress' = 'progress'
const ENABLE_PROGRESS_REPORTING = false // Some MCP clients break when progress reporting is enabled

// Configuration validation schema
const ConfigSchema = z.object({
    maxMemoryMB: z.number().min(256).max(8192).default(512),
    maxCpuPercent: z.number().min(10).max(800).default(50),
    maxPids: z.number().min(50).max(500).default(100),
    timeoutMs: z.number().min(1000).max(300000).default(120000), // Allow up to 5 minutes timeout
})

type Config = z.infer<typeof ConfigSchema>

class VulnerableTarget {
    container: Docker.Container | null = null
    ip: string | null = null

    constructor(
        private docker: Docker,
        private network: Docker.Network
    ) {}

    async start(): Promise<string> {
        try {
            console.log('Pulling Metasploitable2 image...')
            await this.docker.pull(IMAGE_METASPLOITABLE)

            console.log('Creating Metasploitable2 container...')
            this.container = await this.docker.createContainer({
                Image: IMAGE_METASPLOITABLE,
                Cmd: ['sh', '-c', '/bin/services.sh && sleep infinity'],
                // Cmd: ['/bin/services.sh', '&&', 'which', 'sleep'],
                Tty: true,
                AttachStdin: false,
                AttachStdout: false,
                AttachStderr: false,
                ExposedPorts: {
                    '80/tcp': {}, // Expose port 80
                },
                HostConfig: {
                    // NetworkMode: 'none', // Start with no network
                    Memory: 8192 * 1024 * 1024,
                    PortBindings: {
                        '80/tcp': [{ HostPort: '8081' }], // Map container port 80 to host port 8081
                    },
                },
            })

            console.log('Starting Metasploitable2 container...')
            await this.container.start()

            console.log('Connecting Metasploitable2 to network...')
            await this.connectToNetwork(this.container, '172.20.0.3')

            this.ip = '172.20.0.3'
            console.log('Metasploitable2 container ready at', this.ip)
            return this.ip
        } catch (error) {
            console.error('Error starting Metasploitable2:', error)
            await this.cleanup()
            throw error
        }
    }

    async cleanup(): Promise<void> {
        if (this.container) {
            try {
                await this.container.stop()
                await this.container.remove({ force: true })
            } catch (error) {
                console.error('Error cleaning up target container:', error)
            }
            this.container = null
        }
        this.ip = null
    }

    getIp(): string | null {
        return this.ip
    }

    private async connectToNetwork(container: Docker.Container, ipAddress: string): Promise<void> {
        try {
            // First try to disconnect if already connected
            try {
                await this.network?.disconnect({ Container: container.id })
            } catch (error) {
                // Ignore disconnect errors
            }

            // Then connect with the specified IP
            await this.network?.connect({
                Container: container.id,
                EndpointConfig: {
                    IPAMConfig: {
                        IPv4Address: ipAddress,
                    },
                },
            })
        } catch (error) {
            console.error(`Failed to connect container to network: ${error}`)
            throw error
        }
    }
}

class MetasploitContainer {
    private docker: Docker
    private container: Docker.Container | null = null
    private network: Docker.Network | null = null
    private target: VulnerableTarget | null = null
    private isRunning = false
    private readonly rpcPassword: string
    private readonly rpcPort: number
    private readonly config: Config
    private cleanupTimeout: NodeJS.Timeout | null = null
    // biome-ignore lint/suspicious/noExplicitAny: none
    private msfClient: any = null
    private consoleId: string | null = null
    private targetIp: string | null = null

    constructor(config: Config) {
        this.docker = new Docker()
        this.config = config
        this.rpcPassword = crypto.randomBytes(32).toString('hex')
        // this.rpcPort = Math.floor(Math.random() * (65535 - 1024) + 1024)
        this.rpcPort = 55553
    }

    private async findExistingContainers(): Promise<void> {
        const containers = await this.docker.listContainers({ all: true })
        const networks = await this.docker.listNetworks()

        for (const network of networks) {
            if (network.Name.includes('metasploit-network')) {
                console.log(`Found existing network ${network.Name}...`)
                this.network = this.docker.getNetwork(network.Id)
            }
        }
        if (!this.network) return

        for (const container of containers) {
            if (container.Image.includes('metasploitframework')) {
                console.log(`Found existing metasploit container ${container.Id}...`)
                this.container = this.docker.getContainer(container.Id)
            }
            if (container.Image.includes('metasploitable')) {
                console.log(`Found existing metasploitable container ${container.Id}...`)
                if (!this.network) {
                    throw new Error('Network not found')
                }
                this.target = new VulnerableTarget(this.docker, this.network)
                this.target.container = this.docker.getContainer(container.Id)
                this.targetIp = "172.20.0.3"
            }
        }
    }
    private async cleanupExisting(): Promise<void> {
        console.log('Checking for existing containers...')
        const containers = await this.docker.listContainers({ all: true })

        for (const container of containers) {
            if (
                container.Image.includes('metasploitframework') ||
                container.Image.includes('metasploitable')
            ) {
                console.log(`Removing existing container ${container.Id}...`)
                const cont = this.docker.getContainer(container.Id)
                await cont.stop().catch(() => {})
                await cont.remove({ force: true })
            }
        }

        const networks = await this.docker.listNetworks()
        for (const network of networks) {
            if (network.Name.includes('metasploit-network')) {
                console.log(`Removing existing network ${network.Name}...`)
                const net = this.docker.getNetwork(network.Id)
                await net.remove()
            }
        }
    }

    private async createNetwork(): Promise<void> {
            console.log("Creating isolated network...");
            this.network = await this.docker.createNetwork({
                Name: `metasploit-network-${Date.now()}`,
                Driver: "bridge",
                Internal: false, // Allow external connections
                Options: {
                    "com.docker.network.bridge.enable_ip_masquerade":
                        "true", // Enable NAT
                },
                IPAM: {
                    Driver: "default",
                    Config: [
                        {
                            Subnet: "172.20.0.0/16",
                            Gateway: "172.20.0.1",
                        },
                    ],
                },
            });
            console.log("Network created successfully");
    }

    private async createContainer(): Promise<void> {
        console.log("Creating Metasploit container...")
        this.container =
            await this.docker.createContainer({
                Image: IMAGE_METASPLOIT,
                AttachStdin: true,
                AttachStdout: true,
                AttachStderr: true,
                Tty: true,
                OpenStdin: true,
                StdinOnce: false,
                ExposedPorts: {
                    [`${this.rpcPort}/tcp`]: {},
                },
                HostConfig: {
                    PortBindings: {
                        [`${this.rpcPort}/tcp`]: [
                            {
                                HostPort:
                                    this.rpcPort.toString(),
                                HostIp: "127.0.0.1",
                            },
                        ],
                    },
                    SecurityOpt: [
                        "seccomp=unconfined",
                    ],
                    CapAdd: [
                        "NET_ADMIN",
                        "CHOWN",
                        "SETUID",
                        "SETGID",
                        "DAC_OVERRIDE",
                    ],
                    Memory:
                        this.config.maxMemoryMB *
                        1024 *
                        1024,
                    MemorySwap: -1,
                    CpuQuota:
                        this.config.maxCpuPercent *
                        1000,
                    PidsLimit: this.config.maxPids,
                    NetworkMode: this.network.id,
                },
                NetworkingConfig: {
                    EndpointsConfig: {
                        [this.network.id]: {
                            IPAMConfig: {
                                IPv4Address: "172.20.0.2",
                            },
                        },
                    },
                },
                WorkingDir:
                    "/usr/src/metasploit-framework",
                Env: [
                    "LANG=C.UTF-8",
                    "MSF_DISABLE_WEB_UI=1",
                    "MSF_DISABLE_CONSOLE_LOGGING=1",
                    "BUNDLE_SILENCE_ROOT_WARNING=1",
                    "BUNDLE_APP_CONFIG=/usr/src/metasploit-framework/.bundle",
                    "MSF_USER=msf",
                    "MSF_GROUP=msf",
                    "HOME=/home/msf",
                    "PATH=/usr/local/bundle/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                ],
            });

        console.log(
            "Starting Metasploit container...",
        );
        await this.container.start();

        console.log('Waiting for container to stabilize...')
        await new Promise(resolve => setTimeout(resolve, 10000))

        if (!this.targetIp) {
            throw new Error('Target IP not set')
        }
        console.log('Setting up network restrictions...')
        await this.setupNetworkRestrictions(this.targetIp)

        console.log('Dropping elevated privileges...')
        await this.dropPrivileges()

    }

    async startVulnerableContainer(): Promise<void> {
        console.log('Starting vulnerable target container...')
        if (!this.network) {
            throw new Error('Network not found')
        }
        this.target = new VulnerableTarget(this.docker, this.network)
        this.targetIp = await this.target.start()
        console.log('Target container started at', this.targetIp)
    }

    async start(forceNewContainers: boolean): Promise<void> {
        try {
            await this.findExistingContainers()
            if (forceNewContainers || (!this.container || !this.target || !this.network)) {
                await this.cleanupExisting()
                await this.createNetwork()
                await this.startVulnerableContainer()
                await this.createContainer()
            }

            console.log('Starting Metasploit RPC daemon...')
            await this.startMsfrpcd()

            this.isRunning = true
            console.log('Metasploit environment startup complete')
        } catch (error) {
            console.error('Error during Metasploit startup:', error)
            await this.cleanup()
            throw error
        }
    }

    private async setupNetworkRestrictions(targetIp: string): Promise<void> {
        if (!this.container) return

        // Wait for container to be fully running
        let retries = 0
        const maxRetries = 10
        while (retries < maxRetries) {
            try {
                const containerInfo = await this.container.inspect()
                console.log(`Container state (attempt ${retries + 1}/${maxRetries}):`, {
                    id: containerInfo.Id.substring(0, 12),
                    name: containerInfo.Name,
                    image: containerInfo.Config.Image,
                    running: containerInfo.State.Running,
                    status: containerInfo.State.Status,
                    startedAt: containerInfo.State.StartedAt,
                    health: containerInfo.State.Health,
                    exitCode: containerInfo.State.ExitCode,
                    error: containerInfo.State.Error,
                    oomKilled: containerInfo.State.OOMKilled,
                    dead: containerInfo.State.Dead,
                })

                // Get container logs if not running
                if (!containerInfo.State.Running) {
                    const logs = await this.container.logs({
                        stdout: true,
                        stderr: true,
                        tail: 50,
                    })
                    console.log('Container logs:', logs.toString())
                }

                if (containerInfo.State.Running) {
                    break
                }
            } catch (error) {
                console.error('Error checking container state:', error)
            }
            console.log(
                `Container not ready yet, waiting... (attempt ${retries + 1}/${maxRetries})`
            )
            await new Promise(resolve => setTimeout(resolve, 1000))
            retries++
        }

        // Verify container is running
        const containerInfo = await this.container.inspect()
        if (!containerInfo.State.Running) {
            console.error('Container failed to start. Final state:', {
                id: containerInfo.Id.substring(0, 12),
                name: containerInfo.Name,
                image: containerInfo.Config.Image,
                status: containerInfo.State.Status,
                exitCode: containerInfo.State.ExitCode,
                error: containerInfo.State.Error,
            })
            throw new Error('Container not running before network setup')
        }

        const rules = [
            // Allow outbound to target
            ['OUTPUT', '-d', targetIp, '-j', 'ACCEPT'],
            // Allow localhost communication
            ['OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
            ['INPUT', '-i', 'lo', '-j', 'ACCEPT'],
            // Allow incoming connections from host to container for RPC
            ['INPUT', '-p', 'tcp', '--dport', this.rpcPort.toString(), '-j', 'ACCEPT'],
            // Allow outbound connections only for the RPC port
            [
                'OUTPUT',
                '-p',
                'tcp',
                '--sport',
                this.rpcPort.toString(),
                '-d',
                '127.0.0.1',
                '-j',
                'ACCEPT',
            ],
            // Allow established connections only for the RPC port
            [
                'INPUT',
                '-m',
                'state',
                '--state',
                'ESTABLISHED,RELATED',
                '-p',
                'tcp',
                '--sport',
                '127.0.0.1',
                '--dport',
                this.rpcPort.toString(),
                '-j',
                'ACCEPT',
            ],
            [
                'OUTPUT',
                '-m',
                'state',
                '--state',
                'ESTABLISHED,RELATED',
                '-p',
                'tcp',
                '--dport',
                '127.0.0.1',
                '--sport',
                this.rpcPort.toString(),
                '-j',
                'ACCEPT',
            ],
            // Drop everything else outbound
            ['OUTPUT', '!', '-d', targetIp, '-j', 'DROP'],
        ]

        for (const rule of rules) {
            try {
                console.log(`Applying iptables rule: ${rule.join(' ')}`)
                const exec = await this.container.exec({
                    Cmd: ['iptables', '-A', ...rule],
                    AttachStdout: true,
                    AttachStderr: true,
                })

                const stream = await exec.start({})

                // Wait for the command to complete and check for errors
                await new Promise((resolve, reject) => {
                    let output = ''
                    stream.on('data', (chunk: Buffer) => {
                        output += chunk.toString()
                    })
                    stream.on('end', () => {
                        if (output.toLowerCase().includes('error')) {
                            reject(new Error(`iptables error: ${output}`))
                        }
                        console.log(`Successfully applied rule: ${rule.join(' ')}`)
                        resolve(undefined)
                    })
                    stream.on('error', reject)
                })
            } catch (error) {
                console.error('Failed to apply iptables rule:', rule, error)
                throw error
            }
        }
    }

    private async dropPrivileges(): Promise<void> {
        if (!this.container) return

        await this.container.update({
            SecurityOpt: ['no-new-privileges'],
            CapDrop: ['ALL'],
            CapAdd: ['NET_ADMIN'], // Keep only what we need
        })
    }

    private async startMsfrpcd(): Promise<void> {
        if (!this.container) return

        // First, let's check if we can run a simple command in the container
        console.log('Testing container connectivity...')
        // TODO make this quiet
        const testExec = await this.container.exec({
            Cmd: ['ls', '-la', '/usr/src/metasploit-framework'],
            AttachStdout: true,
            AttachStderr: true,
        })

        const testStream = await testExec.start({})
        await new Promise(resolve => {
            testStream.on('data', chunk => {
                ;
                // console.log('Container test output:', `${chunk.toString().substring(0, 100)}...`)
            })
            testStream.on('end', resolve)
        })

        // Kill any existing msfrpcd processes
        console.log("Killing any existing msfrpcd processes...");
        const killExec = await this.container.exec({
            Cmd: ['killall', '-9', 'msfrpcd'],
            AttachStdout: true,
            AttachStderr: true,
        })
        const killStream = await killExec.start({})
        await new Promise(resolve => {
            killStream.on('data', _ => {
                ;
            })
            killStream.on('end', resolve)
        })
        killStream.destroy()

        // Run the RPC daemon directly
        console.log("Starting RPC daemon...");
        const msfrpcdExec = await this.container.exec({
            Cmd: [
                '/usr/src/metasploit-framework/msfrpcd',
                '-P',
                this.rpcPassword,
                '-a',
                '0.0.0.0',
                '-p',
                this.rpcPort.toString(),
                '-U',
                'msf',
                '-n',
                '-f',
                '-S',
                'false',
            ],
            AttachStdin: true,
            AttachStdout: true,
            AttachStderr: true,
            WorkingDir: '/usr/src/metasploit-framework',
        })

        const msfrpcdStream = await msfrpcdExec.start({})

        // Wait for RPC daemon to start
        let output = ''
        await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                reject(new Error('RPC daemon startup timeout'))
            }, 15000)

            msfrpcdStream.on('data', (chunk: Buffer) => {
                const text = chunk.toString()
                // Filter out gem deprecation warnings
                if (
                    !text.includes('Gem::Platform.match') &&
                    !text.includes('will be removed in Rubygems') &&
                    !text.includes('SPELL_CHECKERS.merge')
                ) {
                    output += text
                    console.log('RPC daemon output:', text)
                }
                if (output.includes('MSGRPC')) {
                    // Wait a bit longer to see if there are any errors after startup
                    setTimeout(() => {
                        clearTimeout(timeout)
                        resolve(undefined)
                    }, 5000)
                }
            })
        })

        // Wait a bit for the daemon to fully initialize
        await new Promise(resolve => setTimeout(resolve, 15000))

        // Use msfrpc module to authenticate
        try {
            // Test the connection
            while (true) {
                console.log('Attempting to authenticate to RPC daemon using msfrpc module')
                try {
                    this.msfClient = new MsfRpcClient({
                        uri: `http://127.0.0.1:${this.rpcPort}`,
                        host: '127.0.0.1',
                        port: this.rpcPort,
                        user: 'msf',
                        pass: this.rpcPassword,
                        ssl: false,
                    })
                    await this.msfClient.connect()

                    // Get version info to confirm connection
                    const version = await this.msfClient.core.version()
                    console.log('Connected to Metasploit RPC server:', version)
                    break
                } catch (error) {
                    console.error('Connection failed:', error)
                    await new Promise(resolve => setTimeout(resolve, 1000))
                }
            }
        } catch (error) {
            console.error('Authentication failed:', error)
            throw new Error('Authentication failed')
        }

        // Create a console
        const createResult = await this.msfClient.console.create()
        this.consoleId = createResult.id
        console.log(`Created new console with ID: ${this.consoleId}`)
    }

    async sendCommand(
        command: string,
        reportProgress: (reportProgress: Progress) => void,
        mcpSession: FastMCPSession<Record<string, unknown>>,
        SLOW_RESPONSE_MODE: 'sampling' | 'progress'
    ): Promise<string | ContentResult | TextContent | ImageContent> {
        if (!this.isRunning || !this.msfClient) {
            throw new Error('Metasploit console is not running')
        }

        const sanitizedCommand = this.sanitizeCommand(command)
        if (!sanitizedCommand) {
            throw new Error('Invalid command')
        }

        let progress = 0
        if (ENABLE_PROGRESS_REPORTING) {
            reportProgress({
                progress: progress,
                total: 100,
            });
        }
        try {
            console.log(chalk.yellow(`Executing command via RPC: ${sanitizedCommand}`))

            // Create a console if needed
            if (!this.consoleId) {
                const consoleList = await this.msfClient.console.list()

                if (consoleList.consoles.length === 0) {
                    const createResult = await this.msfClient.console.create()
                    this.consoleId = createResult.id
                    console.log(`Created new console with ID: ${this.consoleId}`)
                } else {
                    this.consoleId = consoleList.consoles[0].id
                    // console.log(`Using existing console with ID: ${consoleId}`);
                }
            }

            // Write the command to the console
            await this.msfClient.console.write(this.consoleId, `${sanitizedCommand}\n`)

            // Read the output with timeout
            let output = ''
            let busy = true
            let prompt = null
            const startTime = Date.now()

            // while (busy && Date.now() - startTime < 90000) {
            while (
                busy &&
                (Date.now() - startTime < this.config.timeoutMs ||
                    (prompt.includes("scan") && sanitizedCommand === "run")) &&
                Date.now() - startTime < 4 * this.config.timeoutMs
            ) {
                if (ENABLE_PROGRESS_REPORTING) {
                    progress += 1;
                    reportProgress({
                        progress: progress,
                        total: 100,
                    });
                }
                await new Promise((resolve) =>
                    setTimeout(resolve, 1000),
                );

                console.log(chalk.red("Read starting"));
                const readResult = await this.msfClient.console.read(
                    this.consoleId,
                );
                console.log(
                    chalk.red('Read returned: "', readResult.data, '"'),
                );
                output += readResult.data;
                busy = readResult.busy;
                prompt = readResult.prompt;
                console.log(chalk.red("Prompt returned: ", prompt));

                if (
                    !busy ||
                    output.includes("[-] Error:") ||
                    output.includes("[!] Failed:") ||
                    output.includes("No results from search") ||
                    output.includes("Auxilliary module execution") ||
                    output.includes("[*] Connected to") ||
                    output.includes("root@") ||
                    /root@[^:]+:\/#/.test(output)
                ) {
                    break;
                }
            }

            if (Date.now() - startTime >= this.config.timeoutMs) {
            // if (Date.now() - startTime >= 90000) {
                console.log(chalk.red('Command execution timeout'))
                // throw new Error('Command execution timeout')
            }

            if (SLOW_RESPONSE_MODE === 'progress') {
                if (ENABLE_PROGRESS_REPORTING) {
                    reportProgress({
                        progress: 100,
                        total: 100,
                    })
                }
            }
            // Colorize output
            console.log('Command output:\n', chalk.green(output))
            console.log('Prompt:\n', chalk.blue(prompt))

            if (SLOW_RESPONSE_MODE === 'sampling') {
                const sampleData: z.infer<typeof CreateMessageRequestSchema>['params'] = {
                    messages: [
                        {
                            role: 'user',
                            content: {
                                type: 'text',
                                // biome-ignore lint/style/useTemplate: none
                                text: `Here is the output of the last command: ${output}\n\n` +
                                      (prompt ? `Here is the prompt: ${prompt}` : ''),
                            },
                        },
                    ],
                    maxTokens: 8000,
                }
                await mcpTopSession.requestSampling(sampleData)
                return ''
            }
            // biome-ignore lint/style/useTemplate: none
            return `Here is the output of the last command: ${output}\n\n` +
                (prompt ? `Here is the prompt: ${prompt}` : '')
        } catch (error) {
            console.error('Error executing command:', error)
            return 'Command execution failed'
            //   throw new UserError("Command execution failed");
        }
    }

    private sanitizeCommand(command: string): string | null {
        // Basic command sanitization and validation
        const sanitized = command.trim()
        // if (!sanitized || sanitized.includes('|') || sanitized.includes(';')) {
        //     return null;
        // }
        return sanitized
    }

    private async cleanup(): Promise<void> {
        console.log('Starting cleanup...')
        if (this.cleanupTimeout) {
            console.log('Clearing cleanup timeout')
            clearTimeout(this.cleanupTimeout)
            this.cleanupTimeout = null
        }

        if (this.container) {
            try {
                const containerInfo = await this.container.inspect()
                if (containerInfo.State.Running) {
                    console.log('Stopping Metasploit container...')
                    await this.container.stop({ t: 10 })
                }
                console.log('Removing Metasploit container...')
                await this.container.remove({ force: true })
            } catch (error) {
                console.error('Error cleaning up Metasploit container:', error)
            } finally {
                this.container = null
            }
        }

        if (this.network) {
            try {
                console.log('Removing network...')
                await this.network.remove()
            } catch (error) {
                console.error('Error removing network:', error)
            } finally {
                this.network = null
            }
        }

        if (this.target) {
            console.log('Cleaning up target container...')
            await this.target.cleanup()
            this.target = null
        }

        this.isRunning = false

        // Close any open consoles
        if (this.msfClient) {
            try {
                const consoleList = await this.msfClient.console.list()
                for (const console of consoleList.consoles) {
                    await this.msfClient.console.destroy(console.id)
                }
            } catch (error) {
                console.error('Error closing consoles:', error)
            }
            this.msfClient = null
        }

        console.log('Cleanup complete')
    }

    async stop(): Promise<void> {
        await this.cleanup()
    }

    isServerRunning(): boolean {
        return this.isRunning
    }
}

let server: FastMCP<Record<string, unknown>>
let mcpTopSession: FastMCPSession<Record<string, unknown>>
export async function createMetasploitServer(container: MetasploitContainer) {
    server = new FastMCP({
        name: 'Metasploit Server',
        version: '1.0.0',
        
        // requestTimeout: 120000,
        //     keepalive: true,
        //     pingInterval: 30000,
        //     pingTimeout: 5000
    })

    // Remove the start event handler since we're starting containers before the server

    server.addTool({
        name: 'msf',
        description:
            SLOW_RESPONSE_MODE === 'sampling'
                ? 'Run any Metasploit Framework console command. This submits the command to the Metasploit Framework asynchronously. The response will be returned asynchronously via sampling.'
                : 'Run any Metasploit Framework console command.',
        parameters: z.object({
            command: z
                .string()
                .min(1)
                .max(1000)
                .describe('The command to run in msfconsole'),
        }),
        execute: async (args, context) => {
            const { log, reportProgress } = context
            if (!container.isServerRunning()) {
                throw new Error('Metasploit environment is not running')
            }

            log.info('Executing command', { command: args.command })
            let response: string | ContentResult | TextContent | ImageContent
            switch (SLOW_RESPONSE_MODE) {
                case 'sampling':
                    container.sendCommand(
                        args.command,
                        reportProgress,
                        mcpTopSession,
                        SLOW_RESPONSE_MODE
                    )
                    response =
                        'Tool has sent command to Metasploit Framework. The response will be returned asynchronously via sampling.'
                    break
                case 'progress':
                    response = await container.sendCommand(
                        args.command,
                        reportProgress,
                        mcpTopSession,
                        SLOW_RESPONSE_MODE
                    )
                    break
            }
            return response
        },
    })

    // Add a status tool to check if containers are running
    server.addTool({
        name: 'status',
        description: 'Check if the Metasploit environment is running',
        parameters: undefined,
        execute: async (_) => {
            const status = container.isServerRunning()
            return JSON.stringify({
                running: status,
                message: status
                    ? 'Metasploit environment is running'
                    : 'Metasploit environment is not running',
            })
        },
    })

    // const mcpTopSession = await new Promise<FastMCPSession>((resolve, reject) => {
    //     console.log("Client connected");
    //     server.on("connect", (event) => {
    //         event.session.on("error", (error: any) => {
    //             reject(error);
    //         })
    //         resolve(event.session);
    //     })
    // })

    server.on('connect', event => {
        console.log('Client connected')
        mcpTopSession = event.session

        // Add error handler to the session itself
        // biome-ignore lint/suspicious/noExplicitAny: none
        event.session.on('error', (error: any) => {
            if (error instanceof Error) {
                if (error.message.includes('ping')) {
                    return
                }
                console.error('Session error:', error.message)
            }
            // Ignore ping errors at the session level
            // if (error?.code === -32601) {
            // cast MCPError
            // const mcpError = error as MCPError;
            // console.log("MCPError:", JSON.stringify(mcpError, null, 2));
            // if (error.message.includes("ping")) {
            //     return;
            // }
            // }
            // console.log("Session error:", JSON.stringify(error, null, 2));
            //   console.error("Session error:", error);
        })
    })

    server.on('disconnect', event => {
        console.log('Client disconnected:', event.session)
    })

    // Add error handler for ping errors
    // server.on('error', (error: any) => {
    //     // More robust error checking
    //     if (
    //         error &&
    //         typeof error === 'object' &&
    //         'code' in error &&
    //         'message' in error &&
    //         error.code === -32601 &&
    //         typeof error.message === 'string' &&
    //         error.message.includes('ping')
    //     ) {
    //         return
    //     }
    //     // Log other errors
    //     console.error('Server error:', error)
    // })

    return server
}

async function main() {
    // get args
    const forceNewContainers = process.argv.includes('--force-new-containers')
    try {
        console.log('Creating Metasploit server...')
        const container = new MetasploitContainer(
            ConfigSchema.parse({
                maxMemoryMB: 8192,
                maxCpuPercent: 800,
                maxPids: 200,
                timeoutMs: 10000,
            })
        )

        console.log('Starting containers...')
        await container.start(forceNewContainers)
        console.log('Containers started successfully')

        console.log('Starting server...')
        const server = await createMetasploitServer(container)
        server.start({
            transportType: 'sse',
            sse: {
                endpoint: '/sse',
                port: 3030,
            },
        })
        console.log('Server started on port 3030')
    } catch (error) {
        if (error instanceof Error) {
            console.error('Failed to start server:', error.message)
        }
        process.exit(1)
    }
}

main()
