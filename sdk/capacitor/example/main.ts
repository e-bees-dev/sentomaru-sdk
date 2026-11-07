// a button that runs the flow on the real plugin. Needs a Capacitor project (see README.md).
import { Sentomaru } from '../src/index.ts';
import { runFlow } from './flow.ts';

const out = document.getElementById('log')!;
document.getElementById('run')!.addEventListener('click', () => {
  void runFlow(Sentomaru, (line) => { out.appendChild(Object.assign(document.createElement('li'), { textContent: line })); });
});
