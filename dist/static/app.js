const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const otpInput = document.getElementById("otp");
const tokenInput = document.getElementById("token");
const resultBox = document.getElementById("result");
const qrCard = document.getElementById("qrCard");
const qrImage = document.getElementById("qrImage");
const qrLink = document.getElementById("qrLink");

function setResult(title, payload) {
    const content = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
    resultBox.textContent = `${title}\n${content}`;
}

function getCredentials() {
    return {
        username: usernameInput.value.trim(),
        password: passwordInput.value,
        otp: otpInput.value.trim(),
        token: tokenInput.value.trim(),
    };
}

function requireFields(fields) {
    const values = getCredentials();
    const missing = fields.find((field) => !values[field]);
    if (missing) {
        setResult("Validation", `Please fill the ${missing} field.`);
        return null;
    }
    return values;
}

async function sendRequest(url, options = {}) {
    const response = await fetch(url, options);
    const contentType = response.headers.get("content-type") || "";
    const data = contentType.includes("application/json")
        ? await response.json()
        : await response.text();

    if (!response.ok) {
        throw new Error(typeof data === "string" ? data : JSON.stringify(data));
    }

    return data;
}

function showQr(username) {
    const qrUrl = `/qr?username=${encodeURIComponent(username)}&t=${Date.now()}`;
    qrImage.src = qrUrl;
    qrLink.href = qrUrl;
    qrCard.hidden = false;
}

document.getElementById("registerBtn").addEventListener("click", async () => {
    const values = requireFields(["username", "password"]);
    if (!values) {
        return;
    }

    try {
        const data = await sendRequest(
            `/register?username=${encodeURIComponent(values.username)}&password=${encodeURIComponent(values.password)}`,
            { method: "POST" },
        );
        showQr(values.username);
        setResult("Register success", data);
    } catch (error) {
        setResult("Register error", error.message);
    }
});

document.getElementById("loginBtn").addEventListener("click", async () => {
    const values = requireFields(["username", "password"]);
    if (!values) {
        return;
    }

    try {
        const data = await sendRequest(
            `/login?username=${encodeURIComponent(values.username)}&password=${encodeURIComponent(values.password)}`,
            { method: "POST" },
        );
        setResult("Login response", data);
    } catch (error) {
        setResult("Login error", error.message);
    }
});

document.getElementById("verifyBtn").addEventListener("click", async () => {
    const values = requireFields(["username", "otp"]);
    if (!values) {
        return;
    }

    try {
        const data = await sendRequest(
            `/verify-otp?username=${encodeURIComponent(values.username)}&otp=${encodeURIComponent(values.otp)}`,
            { method: "POST" },
        );
        tokenInput.value = data.token || "";
        setResult("OTP verified", data);
    } catch (error) {
        setResult("OTP error", error.message);
    }
});

document.getElementById("protectedBtn").addEventListener("click", async () => {
    const values = requireFields(["token"]);
    if (!values) {
        return;
    }

    try {
        const data = await sendRequest("/protected", {
            method: "GET",
            headers: {
                Authorization: `Bearer ${values.token}`,
            },
        });
        setResult("Protected route", data);
    } catch (error) {
        setResult("Protected error", error.message);
    }
});
