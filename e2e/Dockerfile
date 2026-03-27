FROM denoland/deno:2.7.8

WORKDIR /app

COPY deno.json deno.lock ./
COPY mod.ts service.ts types.ts cookies.ts ./
COPY e2e ./e2e

RUN deno cache e2e/app.ts

CMD ["deno", "run", "--unstable-kv", "--allow-env", "--allow-net", "--allow-read", "--allow-write", "e2e/app.ts"]
