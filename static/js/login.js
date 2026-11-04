(() => {
  document.querySelectorAll('.password-toggle').forEach(toggle => {
    const password = toggle.closest('.password-field')?.querySelector('input');
    if (!password) return;

    toggle.addEventListener('click', () => {
      const showPassword = password.type === 'password';
      password.type = showPassword ? 'text' : 'password';
      toggle.setAttribute('aria-pressed', String(showPassword));
      toggle.setAttribute('aria-label', showPassword ? 'Hide password' : 'Show password');
      toggle.title = showPassword ? 'Hide password' : 'Show password';
    });
  });
  const form = document.getElementById('login-form');
  const submit = form?.querySelector('.login-submit');

  const loginLink = [...document.querySelectorAll('.site-header nav a')]
    .find(link => new URL(link.href, window.location.href).pathname === window.location.pathname);
  loginLink?.setAttribute('aria-current', 'page');

  if (form && submit) {
    form.addEventListener('submit', () => {
      submit.disabled = true;
      submit.textContent = 'Logging in\u2026';
      form.setAttribute('aria-busy', 'true');
    });

    window.addEventListener('pageshow', () => {
      submit.disabled = false;
      submit.textContent = 'Log in';
      form.removeAttribute('aria-busy');
    });
  }


})();
