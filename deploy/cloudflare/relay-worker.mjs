import { DurableObject } from "cloudflare:workers";

const relayPort = 8080;
const idleTimeoutMs = 5 * 60 * 1000;

export class RelayContainer extends DurableObject {
  starting;

  async fetch(request) {
    const container = this.ctx.container;
    this.starting ??= this.readyPort(container).finally(() => {
      this.starting = undefined;
    });

    let port;
    try {
      port = await this.starting;
    } catch {
      return Response.json({ error: "Relay unavailable" }, { status: 503 });
    }

    const url = new URL(request.url);
    url.protocol = "http:";
    url.host = "container";
    const forwarded = new Request(url, request);
    forwarded.headers.delete("host");
    return port.fetch(new Request(forwarded, { redirect: "manual" }));
  }

  async readyPort(container) {
    const { DATABASE_URL, PEPE_ADMIN_TOKEN, PEPE_GITHUB_WEBHOOK_SECRET, PEPE_PUBLIC_URL } = this.env;
    if (!DATABASE_URL || !PEPE_ADMIN_TOKEN || !PEPE_GITHUB_WEBHOOK_SECRET || !PEPE_PUBLIC_URL) {
      throw new Error("Missing relay configuration");
    }

    if (!container.running) {
      container.start({
        image: container.images.relay,
        instance: "basic",
        enableInternet: true,
        entrypoint: ["/pepe", "serve", "--listen", `0.0.0.0:${relayPort}`, "--storage", "postgres", "--public-url", PEPE_PUBLIC_URL],
        env: { DATABASE_URL, PEPE_ADMIN_TOKEN, PEPE_GITHUB_WEBHOOK_SECRET },
      });
    }
    await container.setInactivityTimeout(idleTimeoutMs);

    const port = container.getTcpPort(relayPort);
    const deadline = Date.now() + 30_000;
    do {
      try {
        // Any HTTP response proves the listener is up. The public /healthz also checks Postgres.
        const response = await port.fetch("http://container/", { signal: AbortSignal.timeout(1000) });
        await response.body?.cancel();
        return port;
      } catch {
        await scheduler.wait(200);
      }
    } while (Date.now() < deadline);
    throw new Error("Relay did not start");
  }
}

export default {
  fetch(request, env) {
    return env.RELAY.getByName(env.DEPLOYMENT_VERSION.id).fetch(request);
  },
};
