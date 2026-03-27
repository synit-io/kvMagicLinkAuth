const composeFile = new URL("./docker-compose.yml", import.meta.url).pathname;

async function runCommand(args: string[], options: { check?: boolean } = {}) {
  const command = new Deno.Command("docker", {
    args,
    stdout: "inherit",
    stderr: "inherit",
  });
  const result = await command.output();
  if ((options.check ?? true) && !result.success) {
    throw new Error(`Command failed: docker ${args.join(" ")}`);
  }
  return result;
}

async function waitForHealthy(url: string, timeoutMs = 60_000): Promise<void> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Keep polling until the service is ready.
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`Timed out waiting for ${url}`);
}

async function runTests(): Promise<void> {
  const test = new Deno.Command("deno", {
    args: [
      "test",
      "-A",
      "e2e/e2e_test.ts",
    ],
    stdout: "inherit",
    stderr: "inherit",
    env: {
      E2E_AUTH_BASE_URL: "http://127.0.0.1:8080",
      E2E_MAILPIT_BASE_URL: "http://127.0.0.1:8025",
    },
  });
  const result = await test.output();
  if (!result.success) {
    throw new Error("E2E tests failed.");
  }
}

try {
  await runCommand(["compose", "-f", composeFile, "up", "-d", "--build"]);
  await waitForHealthy("http://127.0.0.1:8025/api/v1/info");
  await waitForHealthy("http://127.0.0.1:8080/health");
  await runTests();
} finally {
  await runCommand(["compose", "-f", composeFile, "down", "-v"], {
    check: false,
  });
}
