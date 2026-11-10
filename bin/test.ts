import { assert } from '@japa/assert'
import { configure, processCLIArgs, run } from '@japa/runner'

processCLIArgs(process.argv.splice(2))
configure({
  suites: [
    { name: 'unit', files: ['tests/unit/**/*.spec.ts'] },
    { name: 'integration', files: ['tests/integration/**/*.spec.ts'], timeout: 20_000 },
  ],
  plugins: [assert()],
})

run()
