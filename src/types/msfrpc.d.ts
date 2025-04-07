declare module 'msfrpc' {
    export default class MsfRpcClient {
        constructor(options: {
            uri?: string
            host?: string
            port?: number
            user?: string
            pass?: string
            ssl?: boolean
        })

        connect(): Promise<void>

        core: {
            version(): Promise<any>
        }

        console: {
            list(): Promise<{ consoles: Array<{ id: string }> }>
            create(): Promise<{ id: string }>
            destroy(id: string): Promise<any>
            write(id: string, command: string): Promise<any>
            read(id: string): Promise<{ data: string; busy: boolean }>
        }
    }
}
