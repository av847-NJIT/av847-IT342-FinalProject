const BB_AUTH = (() => {
    const { region, clientId, apiUrl } = window.BB;
    const KEY = "bb_token";
    const messages = {
        UsernameExistsException: "That email is already registered.",
        CodeMismatchException: "That code is incorrect.",
        ExpiredCodeException: "That code has expired. Request a new one.",
        NotAuthorizedException: "Incorrect email or password.",
        UserNotConfirmedException: "Please confirm your email first, using the Register page.",
        LimitExceededException: "Too many attempts. Wait a few minutes and try again.",
    };

    async function idp(action, body) {
        const res = await fetch(`https://cognito-idp.${region}.amazonaws.com/`, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": `AWSCognitoIdentityProviderService.${action}`,
            },
            body: JSON.stringify({ ClientId: clientId, ...body }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            const type = (data.__type || "").split("#").pop();
            if (messages[type]) throw new Error(messages[type]);
            if (type === "InvalidPasswordException" || type === "InvalidParameterException") throw new Error(data.message);
            throw new Error("Something went wrong. Please try again.");
        }
        return data;
    }

    const decode = (t) => {
        try { return JSON.parse(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))); }
        catch { return null; }
    };
    function token() {
        const t = sessionStorage.getItem(KEY);
        if (!t) return null;
        const c = decode(t);
        if (!c || c.exp * 1000 < Date.now()) { sessionStorage.removeItem(KEY); return null; }
        return t;
    }

    const signUp = (email, password, nickname) => idp("SignUp", {
        Username: email, Password: password,
        UserAttributes: [
            { Name: "email", Value: email },
            { Name: "nickname", Value: nickname }, // delete this line if sign-up reports a schema error
        ],
    });
    const confirm = (email, code) => idp("ConfirmSignUp", { Username: email, ConfirmationCode: code });
    const resend = (email) => idp("ResendConfirmationCode", { Username: email });
    async function login(email, password) {
        const d = await idp("InitiateAuth", {
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: { USERNAME: email, PASSWORD: password },
        });
        sessionStorage.setItem(KEY, d.AuthenticationResult.IdToken); // cleared when the tab closes
    }
    const logout = () => sessionStorage.removeItem(KEY);

    async function api(path, auth = false) {
        const t = auth ? token() : null;
        const res = await fetch(apiUrl + path, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
        const data = await res.json().catch(() => ({}));
        if (res.status === 401) { logout(); throw new Error("Your session expired. Please log in again."); }
        if (!res.ok) throw new Error(data.error || data.message || "Request failed.");
        return data;
    }

    function renderNav() {
        const nav = document.getElementById("nav");
        if (!nav) return;
        nav.textContent = "";
        const add = (text, href, cls) => {
            const a = document.createElement("a");
            a.textContent = text; a.href = href;
            if (cls) a.className = cls;
            nav.appendChild(a);
            return a;
        };
        add("Search", "/search.html");
        if (token()) {
            add("Log out", "#").addEventListener("click", (e) => { e.preventDefault(); logout(); location.href = "/index.html"; });
        } else {
            add("Log in", "/login.html");
            add("Register", "/register.html", "cta");
        }
    }
    renderNav();
    return { signUp, confirm, resend, login, logout, token, api };
})();