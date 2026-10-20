const status = document.querySelector('#response-status');
const output = document.querySelector('#response-body');
const route = document.querySelector('#response-route');
const elapsed = document.querySelector('#response-time');
const token = document.querySelector('#token');
const forms = [...document.querySelectorAll('form')];

for (const form of forms) {
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const endpoint = form.id.replace('-form', '');
    const data = Object.fromEntries(new FormData(form));
    const buttons = forms.map(item => item.querySelector('button'));
    const button = form.querySelector('button');
    const original = button.firstChild.textContent;
    buttons.forEach(item => { item.disabled = true; });
    form.setAttribute('aria-busy', 'true');
    button.firstChild.textContent = 'Working... ';
    status.textContent = 'PENDING / COMPONENT REQUEST';
    status.dataset.state = 'pending';
    route.textContent = `POST /api/${endpoint}`;
    output.textContent = 'Waiting for the component...';
    elapsed.textContent = '-- ms';
    const start = performance.now();
    try {
      const response = await fetch(`/api/${endpoint}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data), signal: AbortSignal.timeout(20000),
      });
      const body = await response.json();
      output.textContent = JSON.stringify(body, null, 2);
      const invalid = endpoint === 'validate' && body.valid === false;
      status.textContent = `${response.status} / ${invalid ? 'INVALID TOKEN' : response.ok ? 'SUCCESS' : 'REQUEST REFUSED'}`;
      status.dataset.state = response.ok && !invalid ? 'success' : 'error';
      if (endpoint === 'signup' && response.status === 201) {
        document.querySelector('#login-email').value = data.email;
        document.querySelector('#login-password').focus();
      }
      if (endpoint === 'login') {
        token.value = response.ok && typeof body.token === 'string' ? body.token : '';
        document.querySelector('#token-note').textContent = token.value
          ? 'Token received. Validate it, then try changing a character.'
          : 'Login did not issue a token. Check your credentials and retry.';
        if (token.value) token.focus();
      }
    } catch {
      status.textContent = 'FAILED / CONNECTION';
      status.dataset.state = 'error';
      output.textContent = 'The request could not be completed. Check that the demo server is running, then retry.';
    } finally {
      // Passwords are never copied into the journal, another form, or persistent storage.
      const password = form.querySelector('input[type="password"]');
      if (password) password.value = '';
      elapsed.textContent = `${Math.round(performance.now() - start)} ms`;
      buttons.forEach(item => { item.disabled = false; });
      button.firstChild.textContent = original;
      form.removeAttribute('aria-busy');
    }
  });
}
