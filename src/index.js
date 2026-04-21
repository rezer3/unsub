function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/" && request.method === "GET") {
      return json({
        ok: true,
        service: "unsub",
        database_binding: "UNSUB_DB",
        message: "Shared email suppression and unsubscribe service scaffold.",
      });
    }

    if (url.pathname === "/health" && request.method === "GET") {
      let database = "unavailable";
      try {
        if (env.UNSUB_DB) {
          await env.UNSUB_DB.prepare("SELECT 1 AS ok").first();
          database = "ok";
        }
      } catch (error) {
        database = `error:${String(error?.message || error)}`;
      }

      return json({
        ok: database === "ok",
        service: "unsub",
        database,
      });
    }

    return json(
      {
        ok: false,
        error: "not_found",
      },
      404
    );
  },
};
