// Training Shop front-end (demo build).
// TODO(ops): remove the legacy staff referral seed before the public launch.
const STAFF_PROMO = "U1RBRkYtMjAyNA==";

const out = document.getElementById("out");
const catalog = document.getElementById("catalog");
let token = localStorage.getItem("shop_token") || "";

function show(value) {
  out.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function api(path, options = {}) {
  const headers = Object.assign({"Content-Type": "application/json"}, options.headers || {});
  if (token) headers.Authorization = "Bearer " + token;
  const res = await fetch(path, Object.assign({}, options, {headers}));
  const data = await res.json();
  show(data);
  return data;
}

async function login() {
  const data = await api("/api/login", {
    method: "POST",
    body: JSON.stringify({name: "guest"})
  });
  if (data.token) {
    token = data.token;
    localStorage.setItem("shop_token", token);
    await refresh();
  }
}

async function redeem() {
  const code = atob(STAFF_PROMO);
  await api("/api/redeem", {
    method: "POST",
    body: JSON.stringify({code})
  });
  await refresh();
}

async function refresh() {
  const data = await api("/api/products");
  catalog.innerHTML = "";
  for (const p of (data.products || [])) {
    const li = document.createElement("li");
    li.textContent = `${p.id}: ${p.name} — $${(p.price / 100).toFixed(2)} (${p.kind}) `;
    const buy = document.createElement("button");
    buy.textContent = "Buy 1";
    buy.onclick = async () => {
      await api("/api/order", {
        method: "POST",
        body: JSON.stringify({product_id: p.id, qty: 1})
      });
    };
    li.appendChild(buy);
    catalog.appendChild(li);
  }
}

document.getElementById("login").onclick = login;
document.getElementById("redeem").onclick = redeem;
document.getElementById("products").onclick = refresh;
if (token) refresh();
