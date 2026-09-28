// Copies the built frontend into the Android wrapper's www/ folder.
// Run after `npm run build`:  npm run build:android
import { cpSync, rmSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = resolve(root, 'dist');
const www = resolve(root, 'android/app/src/main/assets/www');

if (!existsSync(dist)) {
  console.error('dist/ not found - run `npm run build` first.');
  process.exit(1);
}

// The android www folder also holds orvyn-logo.png, so only replace the
// files Vite emits rather than wiping the whole directory.
if (!existsSync(www)) mkdirSync(www, { recursive: true });
rmSync(resolve(www, 'assets'), { recursive: true, force: true });

cpSync(dist, www, { recursive: true });

console.log('Synced dist/ -> android/app/src/main/assets/www');
console.log('Rebuild the APK:  cd android && ./gradlew assembleDebug');
