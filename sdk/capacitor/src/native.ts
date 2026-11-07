// Capacitor plugin calls take and return one object. The native `call` takes {method, args} and resolves {value}
// (Capacitor resolves objects only), so the entry the facade sees unwraps it. No other logic.
import type { NativeSentomaru } from './types.ts';

export interface CapacitorSentomaruPlugin {
  call(options: { method: string; args: Record<string, unknown> }): Promise<{ value?: unknown }>;
}

export function fromPlugin(plugin: CapacitorSentomaruPlugin): NativeSentomaru {
  return {
    call: async (method, args) => {
      const reply = await plugin.call({ method, args });
      return reply?.value ?? null;
    },
  };
}
