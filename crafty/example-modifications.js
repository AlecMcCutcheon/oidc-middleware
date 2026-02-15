/**
 * Crafty middleware does not override the Crafty Controller app's JavaScript.
 * We use a dedicated /login path: the proxy sends /login to the middleware, which
 * redirects to the IdP. After OIDC callback we set the token in a cookie and redirect.
 *
 * Logout: Our only logout UI is the "Cancel and log out" link on the MFA page: <a href="/logout">.
 * The middleware's GET /logout clears the cookie and redirects to the IdP end-session URL.
 *
 * The MFA page (/mfa) is server-rendered HTML from the middleware. It includes inline <script>
 * for the form behavior. Excerpt of that script (conceptually) is below — not injected into
 * the Crafty app, but part of the middleware-served MFA page.
 */

// ========== Excerpt: MFA page inline script (middleware-served HTML) ==========
// Toggle between TOTP code and backup code mode
function toggleMode() {
    isBackupMode = !isBackupMode;
    var toggle = document.getElementById('toggleSwitch');
    var label = document.getElementById('inputLabel');
    var hint = document.getElementById('inputHint');
    var input = document.getElementById('mfaCode');
    var hiddenInput = document.getElementById('isBackupCode');

    if (isBackupMode) {
        toggle.classList.add('active');
        label.textContent = 'Backup Code';
        hint.textContent = 'Enter your backup recovery code';
        input.placeholder = 'Enter backup code';
        input.maxLength = 20;
        hiddenInput.value = 'true';
    } else {
        toggle.classList.remove('active');
        label.textContent = 'TOTP Code';
        hint.textContent = 'Enter the 6-digit code from your authenticator app';
        input.placeholder = '000000';
        input.maxLength = 6;
        hiddenInput.value = 'false';
    }
    input.value = '';
    input.focus();
}

// Form submit: disable button, show "Verifying...", hide error
document.getElementById('mfaForm').addEventListener('submit', function(e) {
    var btn = document.getElementById('submitBtn');
    var errorMsg = document.getElementById('errorMessage');
    btn.disabled = true;
    btn.textContent = 'Verifying...';
    errorMsg.classList.remove('show');
});

// TOTP input: allow only digits, max 6 (when not in backup mode)
document.getElementById('mfaCode').addEventListener('input', function(e) {
    if (!isBackupMode) {
        this.value = this.value.replace(/[^0-9]/g, '').slice(0, 6);
    }
});

// ========== No client-side modifications to the Crafty app itself ==========
// The app's panel JS is unchanged. All our logic is in the middleware (Python) and
// the /login path override; CSS overrides are in static/assets/css/crafty.css (see example-modifications.css).
