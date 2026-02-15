/**
 * Example: pattern for NPM (React-built) login page modifications.
 * We do NOT ship a small patch; we override the app's built bundle (e.g. index-*.js).
 * React controls the DOM, so appending to the existing form was overwritten.
 * Our approach: hide the app's login form and render our own form that POSTs to
 * the middleware's /api/tokens proxy (which adds Turnstile + lockout, then forwards to NPM).
 *
 * We also override the app's logout: find the logout link and replace its behavior
 * so OIDC users go to /logout (middleware clears token and redirects to IdP end-session),
 * while form-login users just get localStorage cleared and a hard refresh.
 *
 * This file is a standalone ILLUSTRATION — the real code lives inside our copy of the minified bundle.
 */
(function() {
    "use strict";

    var API_TOKENS = "/api/tokens";  // middleware proxy

    function hideAppLoginForm() {
        var form = document.querySelector("form");
        if (form) form.style.display = "none";
    }

    function renderOurLoginForm(container) {
        if (document.getElementById("oidc-npm-login-form")) return;
        var div = document.createElement("div");
        div.id = "oidc-npm-login-form";
        div.innerHTML =
            '<form method="post" action="' + API_TOKENS + '">' +
            '  <input type="text" name="identity" placeholder="Email" required />' +
            '  <input type="password" name="secret" placeholder="Password" required />' +
            '  <div id="cf-turnstile-widget"></div>' +
            '  <button type="submit">Log in</button>' +
            '</form>';
        container.appendChild(div);
    }

    function init() {
        var container = document.querySelector(".login-container, .panel-body, [class*='login']");
        if (!container) return;
        hideAppLoginForm();
        renderOurLoginForm(container);
        // Load Turnstile script and render widget (site key from your config)
        // Then form submit goes to middleware -> NPM.
    }

    // --- Logout override: OIDC -> /logout; form login -> clear + refresh ---
    function setupOidcLogout() {
        var logoutSpan = document.querySelector('span[data-translation-id="user.logout"]');
        if (!logoutSpan) return false;
        var logoutButton = logoutSpan.closest("a");
        if (!logoutButton) return false;

        logoutSpan.removeAttribute("data-translation-id");
        logoutButton.id = "npm-oidc-logout";
        logoutButton.addEventListener("click", function(e) {
            e.preventDefault();
            if (localStorage.getItem("oidc_login") === "true") {
                window.location.href = "/logout";
                return;
            }
            localStorage.removeItem("authentications");
            localStorage.removeItem("oidc_login");
            window.location.href = "/";
            window.location.reload(true);
        });
        logoutButton.setAttribute("href", "#");
        return true;
    }

    function initWithLogout() {
        init();
        if (!setupOidcLogout()) {
            setTimeout(function() {
                if (setupOidcLogout()) return;
                var observer = new MutationObserver(function() {
                    if (setupOidcLogout()) observer.disconnect();
                });
                var body = document.body;
                if (body) observer.observe(body, { childList: true, subtree: true });
                setTimeout(function() { observer.disconnect(); }, 10000);
            }, 500);
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initWithLogout);
    } else {
        initWithLogout();
    }
})();
