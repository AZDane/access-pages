export function createAdminApi(adminToken) {
  return Object.freeze({
    async fetch(path, options = {}) {
      const headers = new Headers(options.headers || {});
      if (adminToken) {
        headers.set("X-Admin-Token", adminToken);
      }

      return window.fetch(path, {...options, headers});
    },
  });
}
