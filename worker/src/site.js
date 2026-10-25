export default {
  fetch(request, env) {
    const url = new URL(request.url);

    if (url.protocol === "http:") {
      const location = "https://" + url.host + url.pathname + url.search;
      return new Response(null, { status: 301, headers: { Location: location } });
    }

    return env.ASSETS.fetch(request);
  },
};
