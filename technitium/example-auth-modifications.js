/**
 * Example: modifications we add to the app's auth.js for Technitium DNS.
 * The app's login page loads /js/auth.js. We serve our copy that includes
 * the original app code plus this injection logic. Replace YOUR_TURNSTILE_SITE_KEY
 * and the button text/link with your IdP.
 */

// --- 1) Inject OIDC login section + form tweaks + feedback divs + Turnstile + submit override ---
(function() {
    var TURNSTILE_SITE_KEY = "YOUR_TURNSTILE_SITE_KEY";

    function injectOidcLoginSection() {
        var loginForm = document.querySelector(".pageLogin .panel-body form");
        if (!loginForm) return;
        // Form layout: use our class so CSS can control stacked layout (same width as OIDC section)
        if (loginForm.classList.contains("form-horizontal")) {
            loginForm.classList.remove("form-horizontal");
            loginForm.classList.add("form-login-stacked");
        }
        // Placeholder and panel title (only set when needed)
        var txtUser = document.getElementById("txtUser");
        if (txtUser && txtUser.getAttribute("placeholder") !== "Username") txtUser.setAttribute("placeholder", "Username");
        var txtPass = document.getElementById("txtPass");
        if (txtPass && txtPass.getAttribute("placeholder") !== "Password") txtPass.setAttribute("placeholder", "Password");
        var panelTitle = document.querySelector(".pageLogin .panel-heading .panel-title");
        if (panelTitle && panelTitle.textContent !== "Login to your account") panelTitle.textContent = "Login to your account";

        if (document.querySelector(".oidc-login-section")) return;

        var oidcSection = document.createElement("div");
        oidcSection.className = "oidc-login-section";
        oidcSection.innerHTML =
            '<div class="oidc-login-divider"><span>OR</span></div>' +
            '<a href="/login" class="oidc-login-button">' +
            '<span class="icon"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 8v-2a2 2 0 0 0 -2 -2h-7a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2 -2v-2"></path><path d="M9 12h12l-3 -3"></path><path d="M18 15l3 -3"></path></svg></span>' +
            '<span class="button-text">Login With SSO</span>' +
            '</a>' +
            '<div class="description">Use your identity provider to sign in securely</div>';
        loginForm.parentNode.insertBefore(oidcSection, loginForm.nextSibling);

        // Inline error holders under username and password (instead of hidden AlertPlaceholder)
        var colUser = txtUser && txtUser.closest(".col-sm-8");
        if (colUser && !document.getElementById("technitium-login-feedback-user")) {
            var div = document.createElement("div");
            div.id = "technitium-login-feedback-user";
            div.className = "text-danger";
            div.style.cssText = "display:none; margin-top:4px; font-size:13px;";
            colUser.appendChild(div);
        }
        var colPass = txtPass && txtPass.closest(".col-sm-8");
        if (colPass && !document.getElementById("technitium-login-feedback-pass")) {
            var div = document.createElement("div");
            div.id = "technitium-login-feedback-pass";
            div.className = "text-danger";
            div.style.cssText = "display:none; margin-top:4px; font-size:13px;";
            colPass.appendChild(div);
        }
        // Turnstile container under login button (once per form)
        var btnLogin = document.getElementById("btnLogin");
        if (btnLogin && !document.getElementById("technitium-turnstile-container")) {
            var container = document.createElement("div");
            container.id = "technitium-turnstile-container";
            container.style.cssText = "margin-bottom:14px; text-align:center;";
            container.innerHTML =
                '<div id="technitium-turnstile-widget"></div>' +
                '<div id="technitium-turnstile-feedback" class="text-danger" style="display:none; margin-top:6px; font-size:13px;"></div>' +
                '<div id="technitium-login-attempts-feedback" class="text-danger" style="display:none; margin-top:6px; font-size:13px;"></div>';
            btnLogin.closest(".form-group").insertBefore(container, btnLogin.closest(".form-group").firstChild);
            btnLogin.disabled = true;
            loadTechnitiumTurnstileScript();
        }
        // Form submit: prevent default, always call login() so validation/Turnstile run
        if (loginForm && !loginForm.getAttribute("data-technitium-submit-bound")) {
            loginForm.setAttribute("data-technitium-submit-bound", "true");
            loginForm.addEventListener("submit", function(e) {
                e.preventDefault();
                login();  // app's login() (we may wrap it to add Turnstile token)
                return false;
            });
        }
    }

    function loadTechnitiumTurnstileScript() {
        if (document.getElementById("cf-turnstile-script-technitium")) return;
        var script = document.createElement("script");
        script.id = "cf-turnstile-script-technitium";
        script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onTechnitiumTurnstileLoaded";
        script.onload = function() { renderTechnitiumTurnstile(); };
        document.head.appendChild(script);
    }
    window.onTechnitiumTurnstileLoaded = function() { renderTechnitiumTurnstile(); };
    window.onTechnitiumTurnstileSuccess = function() {
        var btn = document.getElementById("btnLogin");
        if (btn) btn.disabled = false;
        var fb = document.getElementById("technitium-turnstile-feedback");
        if (fb) { fb.textContent = ""; fb.style.display = "none"; }
    };
    window.onTechnitiumTurnstileError = function() {
        var btn = document.getElementById("btnLogin");
        if (btn) btn.disabled = true;
    };
    window.onTechnitiumTurnstileExpired = function() {
        var btn = document.getElementById("btnLogin");
        if (btn) btn.disabled = true;
    };
    var technitiumTurnstileWidgetId = null;
    function resetTechnitiumTurnstile() {
        if (window.turnstile && technitiumTurnstileWidgetId != null) {
            try { window.turnstile.reset(technitiumTurnstileWidgetId); } catch (e) {}
        }
        var btn = document.getElementById("btnLogin");
        if (btn) btn.disabled = true;
    }
    window.resetTechnitiumTurnstile = resetTechnitiumTurnstile;
    function renderTechnitiumTurnstile() {
        var container = document.getElementById("technitium-turnstile-widget");
        if (!container || container.getAttribute("data-turnstile-rendered") === "true") return;
        if (!window.turnstile) return;
        try {
            technitiumTurnstileWidgetId = window.turnstile.render(container, {
                sitekey: TURNSTILE_SITE_KEY,
                theme: "auto",
                size: "normal",
                callback: function() { if (window.onTechnitiumTurnstileSuccess) window.onTechnitiumTurnstileSuccess(); },
                "error-callback": function() { if (window.onTechnitiumTurnstileError) window.onTechnitiumTurnstileError(); },
                "expired-callback": function() { if (window.onTechnitiumTurnstileExpired) window.onTechnitiumTurnstileExpired(); }
            });
            container.setAttribute("data-turnstile-rendered", "true");
        } catch (e) {}
    }

    injectOidcLoginSection();
    var container = document.querySelector(".container");
    if (container) {
        var observer = new MutationObserver(function() { injectOidcLoginSection(); });
        observer.observe(container, { childList: true, subtree: true, attributes: true, attributeFilter: ["style", "class"] });
    }
    setInterval(injectOidcLoginSection, 500);
    // Optional: periodically update user display name if missing (e.g. after OIDC login)
    setInterval(function() {
        var el = document.getElementById("mnuUserDisplayName");
        if (el && (!el.textContent || !el.textContent.trim())) updateUserDisplayName();
    }, 1000);
})();

// --- 2) Override logout: OIDC users go to middleware /logout; others use app logout ---
// The app's original logout() is replaced with this. If user logged in via OIDC
// (localStorage oidc_login === "true", set in callback), we redirect to /logout so
// the middleware can call Technitium API logout, clear cookies, and redirect to IdP
// end-session. Otherwise we use the original Technitium api/user/logout.
function logout() {
    var oidcLogin = localStorage.getItem("oidc_login");

    if (oidcLogin === "true") {
        localStorage.removeItem("token");
        localStorage.removeItem("oidc_login");
        sessionData = null;
        window.location.href = "/logout";
    } else {
        // Original Technitium logout (HTTPRequest to api/user/logout?token=...)
        HTTPRequest({
            url: "api/user/logout?token=" + sessionData.token,
            success: function (responseJSON) {
                localStorage.removeItem("token");
                localStorage.removeItem("oidc_login");
                sessionData = null;
                showPageLogin();
                if (typeof window.resetTechnitiumTurnstile === "function") window.resetTechnitiumTurnstile();
            },
            error: function () {
                localStorage.removeItem("token");
                localStorage.removeItem("oidc_login");
                sessionData = null;
                showPageLogin();
                if (typeof window.resetTechnitiumTurnstile === "function") window.resetTechnitiumTurnstile();
            }
        });
    }
}
