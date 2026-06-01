export type CryptoEventContext = {
  operation: string
} & Record<string, string | number | boolean | undefined>

type CryptoEventSink = (context: CryptoEventContext) => void

let cryptoEventSink: CryptoEventSink | null = (context) => {
  console.info(`[crypto] ${context.operation}`, context)
}

export function setCryptoEventSink(sink: CryptoEventSink | null): void {
  cryptoEventSink = sink
}

export function emitCryptoEvent(context: CryptoEventContext): void {
  cryptoEventSink?.(context)
}
