import { deriveKey, generateSalt } from '../src/kdf/argon2.js';

const PASSPHRASE = 'benchmark-passphrase-test';

interface BenchConfig {
  label: string;
  memoryCost: number;
  timeCost: number;
}

const configs: BenchConfig[] = [
  { label: '16 MiB / t=2', memoryCost: 16384, timeCost: 2 },
  { label: '32 MiB / t=2', memoryCost: 32768, timeCost: 2 },
  { label: '32 MiB / t=3', memoryCost: 32768, timeCost: 3 },
  { label: '64 MiB / t=2', memoryCost: 65536, timeCost: 2 },
  { label: '64 MiB / t=3 (default)', memoryCost: 65536, timeCost: 3 },
  { label: '128 MiB / t=2', memoryCost: 131072, timeCost: 2 },
  { label: '128 MiB / t=3', memoryCost: 131072, timeCost: 3 },
];

async function bench(config: BenchConfig): Promise<number> {
  const salt = generateSalt();
  const start = performance.now();
  await deriveKey(PASSPHRASE, salt, {
    memoryCost: config.memoryCost,
    timeCost: config.timeCost,
    parallelism: 1,
    hashLength: 32,
  });
  return performance.now() - start;
}

async function main() {
  console.log('Argon2id Benchmark');
  console.log('==================');
  console.log(`Platform: ${process.platform} ${process.arch}`);
  console.log(`Node.js: ${process.version}`);
  console.log(`Target: 500ms - 1000ms derivation time\n`);

  // Warmup
  await bench(configs[0]);

  for (const config of configs) {
    const times: number[] = [];
    for (let i = 0; i < 3; i++) {
      times.push(await bench(config));
    }
    const avg = times.reduce((a, b) => a + b) / times.length;
    const marker = avg >= 500 && avg <= 1000 ? ' <-- TARGET' : avg > 1000 ? ' (too slow)' : ' (too fast)';
    console.log(`${config.label.padEnd(25)} ${avg.toFixed(0).padStart(6)}ms avg${marker}`);
  }
}

main().catch(console.error);
