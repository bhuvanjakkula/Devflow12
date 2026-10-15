// Shared local bearer-token prompt. Tokens stay in this page's memory only.
(() => {
  const originalFetch = window.fetch.bind(window);
  let token = null;
  let pending = null;
  function askToken() {
    if (pending) return pending;
    pending = new Promise(resolve => {
      const dialog = document.createElement('dialog');
      const form = document.createElement('form');
      const title = document.createElement('h2');
      title.textContent = 'DevFlow API access';
      const label = document.createElement('label');
      label.textContent = 'Enter your API access token';
      const input = document.createElement('input');
      input.type = 'password'; input.autocomplete = 'off'; input.required = true;
      const submit = document.createElement('button');
      submit.type = 'submit'; submit.textContent = 'Unlock this page';
      const cancel = document.createElement('button');
      cancel.type = 'button'; cancel.textContent = 'Cancel';
      const finish = value => {dialog.remove(); pending = null; resolve(value);};
      form.onsubmit = event => {event.preventDefault(); finish(input.value);};
      cancel.onclick = () => finish(null);
      dialog.oncancel = event => {event.preventDefault(); finish(null);};
      label.append(input); form.append(title, label, submit, cancel); dialog.append(form);
      document.body.append(dialog); dialog.showModal(); input.focus();
    });
    return pending;
  }
  window.fetch = async (resource, options = {}) => {
    const url = new URL(resource instanceof Request ? resource.url : resource, location.href);
    if (url.origin !== location.origin || !url.pathname.startsWith('/api/')) return originalFetch(resource, options);
    const withToken = value => {
      const headers = new Headers(options.headers || (resource instanceof Request ? resource.headers : undefined));
      if (value) headers.set('Authorization', 'Bearer ' + value);
      return {...options, headers};
    };
    let response = await originalFetch(resource, withToken(token));
    if (response.status === 401) {
      if (response.headers.get('X-DevFlow-Login') === '/owner/login') {
        location.assign('/owner/login');
        return response;
      }
      token = await askToken();
      if (token) {
        response = await originalFetch(resource, withToken(token));
        if (response.status === 401) token = null;
      }
    }
    return response;
  };
})();
