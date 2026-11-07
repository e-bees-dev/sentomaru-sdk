// TurboModule spec (codegen) of the native module `Sentomaru`. One method, `call`, as the Kotlin module has: the
// method names and arguments are those of contracts/sdk/hybrid-bridge-v1.json, so the native side never grows with the
// contract. Read by the React Native codegen in an app with the new architecture; with the old one (or the interop layer
// of the new one) the same module is reached through NativeModules.
import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

export interface Spec extends TurboModule {
  call(method: string, args: Object): Promise<Object>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Sentomaru');
